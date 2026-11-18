from datetime import timedelta

import pytest
from acapy_agent.core.plugin_registry import PluginRegistry
from acapy_agent.wallet.keys.manager import MultikeyManager
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from x509_certs import routes
from x509_certs.certs import to_pem, to_x5c

from .conftest import NOW, Pki, wallet_public_key


class Request:
    def __init__(self, context, body=None, query=None, match_info=None):
        self._context = context
        self._body = body or {}
        self.query = query or {}
        self.match_info = match_info or {}
        self.headers = {}
        self.path = "/x509"
        self.method = "POST"

    async def json(self):
        return self._body

    def __getitem__(self, key):
        return {"context": self._context}[key]


def chain_pem(*certs) -> str:
    return "".join(to_pem(c) for c in certs)


async def call(handler, context, **kwargs):
    import json

    return json.loads((await handler(Request(context, **kwargs))).body)


@pytest.mark.asyncio
async def test_plugin_loading_registers_working_routes(context, multikey):
    @web.middleware
    async def inject_context(request, handler):
        request["context"] = context
        return await handler(request)

    registry = PluginRegistry()
    assert registry.register_plugin("x509_certs") is not None
    await registry.init_context(context.profile.context)
    app = web.Application(middlewares=[inject_context])
    app["swagger_dict"] = {}
    await registry.register_admin_routes(app)
    registry.post_process_routes(app)
    assert any(tag["name"] == "x509" for tag in app["swagger_dict"]["tags"])

    async with TestClient(TestServer(app)) as client:
        response = await client.get("/x509/certificates")
        assert response.status == 200
        assert await response.json() == {"results": []}

        response = await client.post(
            "/x509/csr",
            json={"multikey": multikey, "subject": {"common_name": "Standalone"}},
        )
        assert response.status == 200
        csr = x509.load_pem_x509_csr((await response.json())["csr"].encode())
        assert csr.is_signature_valid
        assert csr.public_key() == wallet_public_key(multikey)


@pytest.mark.asyncio
async def test_certificate_crud(context, pki: Pki, multikey):
    leaf = pki.leaf(wallet_public_key(multikey))
    created = await call(
        routes.import_certificate,
        context,
        body={
            "chain": chain_pem(leaf, pki.intermediate, pki.root),
            "purpose": "sd_jwt_vc_issuer",
        },
    )
    assert created["multikey"] == multikey
    assert created["x5c"] == to_x5c([leaf, pki.intermediate, pki.root])
    assert created["subject"] == "CN=Leaf"
    cert_id = created["cert_id"]

    fetched = await call(routes.get_certificate, context, match_info={"cert_id": cert_id})
    assert fetched["cert_id"] == cert_id

    by_key = await call(routes.list_certificates, context, query={"multikey": multikey})
    assert [r["cert_id"] for r in by_key["results"]] == [cert_id]
    by_purpose = await call(
        routes.list_certificates, context, query={"purpose": "mdoc_ds"}
    )
    assert by_purpose["results"] == []
    later = (NOW + timedelta(days=60)).isoformat()
    assert (await call(routes.list_certificates, context, query={"valid_at": later}))[
        "results"
    ] == []

    await call(routes.delete_certificate, context, match_info={"cert_id": cert_id})
    with pytest.raises(web.HTTPNotFound):
        await call(routes.get_certificate, context, match_info={"cert_id": cert_id})


@pytest.mark.asyncio
async def test_list_certificates_by_kid(context, pki: Pki, multikey):
    async with context.session() as session:
        await MultikeyManager(session).update(multikey, "issuer-key-1")
    leaf = pki.leaf(wallet_public_key(multikey))
    await call(
        routes.import_certificate,
        context,
        body={"chain": chain_pem(leaf, pki.intermediate), "purpose": "mdoc_ds"},
    )

    found = await call(routes.list_certificates, context, query={"kid": "issuer-key-1"})
    assert [r["multikey"] for r in found["results"]] == [multikey]
    missing = await call(routes.list_certificates, context, query={"kid": "unknown"})
    assert missing["results"] == []


@pytest.mark.asyncio
async def test_import_certificate_rejections(context, pki: Pki, multikey):
    leaf = pki.leaf(wallet_public_key(multikey))
    stranger = pki.leaf(ec.generate_private_key(ec.SECP256R1()).public_key())
    for chain, reason in [
        (chain_pem(stranger, pki.intermediate), "not in the wallet"),
        (chain_pem(pki.intermediate, leaf), "not issued by"),
        ("garbage", "Invalid PEM"),
    ]:
        with pytest.raises(web.HTTPBadRequest, match=reason):
            await call(
                routes.import_certificate,
                context,
                body={"chain": chain, "purpose": "sd_jwt_vc_issuer"},
            )


@pytest.mark.asyncio
async def test_create_csr(context, multikey):
    result = await call(
        routes.create_csr,
        context,
        body={"multikey": multikey, "subject": {"common_name": "Issuer"}},
    )
    assert result["csr"].startswith("-----BEGIN CERTIFICATE REQUEST-----")

    with pytest.raises(web.HTTPBadRequest, match="Invalid multikey"):
        await call(
            routes.create_csr,
            context,
            body={"multikey": "zXXXX", "subject": {"common_name": "Issuer"}},
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra, reason",
    [
        ({"subject": {"country": "Canada"}}, "Invalid subject"),
        ({"dns_names": ["exämple.com"]}, "Invalid subject alternative name"),
    ],
)
async def test_create_csr_rejects_invalid_names(context, multikey, extra, reason):
    body = {"multikey": multikey, "subject": {"common_name": "Issuer"}, **extra}
    with pytest.raises(web.HTTPBadRequest, match=reason):
        await call(routes.create_csr, context, body=body)


@pytest.mark.asyncio
async def test_self_signed_disabled_by_default(context, multikey):
    with pytest.raises(web.HTTPForbidden):
        await call(
            routes.create_self_signed,
            context,
            body={
                "multikey": multikey,
                "subject": {"common_name": "Demo"},
                "purpose": "sd_jwt_vc_issuer",
            },
        )


@pytest.mark.asyncio
async def test_self_signed_when_enabled(context, multikey):
    context.settings["plugin_config"] = {"x509": {"allow_self_signed": True}}
    created = await call(
        routes.create_self_signed,
        context,
        body={
            "multikey": multikey,
            "subject": {"common_name": "Demo"},
            "purpose": "sd_jwt_vc_issuer",
            "days": 7,
        },
    )
    assert created["multikey"] == multikey
    assert created["subject"] == created["issuer"] == "CN=Demo"


@pytest.mark.asyncio
async def test_trust_anchor_crud(context, pki: Pki):
    created = await call(
        routes.import_trust_anchor,
        context,
        body={
            "certificate_pem": to_pem(pki.root),
            "purpose": "sd_jwt_vc_ca",
            "label": "root",
        },
    )
    anchor_id = created["anchor_id"]
    assert created["subject"] == "CN=Test Root"

    listed = await call(
        routes.list_trust_anchors, context, query={"purpose": "sd_jwt_vc_ca"}
    )
    assert [r["anchor_id"] for r in listed["results"]] == [anchor_id]
    assert (await call(routes.list_trust_anchors, context, query={"purpose": "iaca"}))[
        "results"
    ] == []

    await call(routes.delete_trust_anchor, context, match_info={"anchor_id": anchor_id})
    with pytest.raises(web.HTTPNotFound):
        await call(routes.get_trust_anchor, context, match_info={"anchor_id": anchor_id})


@pytest.mark.asyncio
async def test_import_trust_anchor_rejections(context, pki: Pki, multikey):
    leaf = pki.leaf(wallet_public_key(multikey))
    for pem, reason in [
        (to_pem(leaf), "not a CA"),
        (chain_pem(pki.intermediate, pki.root), "one certificate"),
    ]:
        with pytest.raises(web.HTTPBadRequest, match=reason):
            await call(
                routes.import_trust_anchor,
                context,
                body={"certificate_pem": pem, "purpose": "iaca"},
            )


@pytest.mark.asyncio
async def test_verify_uses_only_matching_anchor_purpose(context, pki: Pki, multikey):
    leaf = pki.leaf(wallet_public_key(multikey))
    anchor = await call(
        routes.import_trust_anchor,
        context,
        body={"certificate_pem": to_pem(pki.root), "purpose": "sd_jwt_vc_ca"},
    )
    x5c = to_x5c([leaf, pki.intermediate])

    ok = await call(
        routes.verify, context, body={"x5c": x5c, "purpose": "sd_jwt_vc_issuer"}
    )
    assert ok == {"verified": True, "anchor_id": anchor["anchor_id"]}

    pem = await call(
        routes.verify,
        context,
        body={"chain": chain_pem(leaf, pki.intermediate), "purpose": "sd_jwt_vc_issuer"},
    )
    assert pem["verified"] is True

    # The root is trusted only for SD-JWT VC issuers, not mdoc document signers.
    mdoc = await call(routes.verify, context, body={"x5c": x5c, "purpose": "mdoc_ds"})
    assert mdoc["verified"] is False

    later = (NOW + timedelta(days=60)).isoformat()
    expired = await call(
        routes.verify,
        context,
        body={"x5c": x5c, "purpose": "sd_jwt_vc_issuer", "at": later},
    )
    assert expired["verified"] is False

    with pytest.raises(web.HTTPBadRequest, match="exactly one"):
        await call(routes.verify, context, body={"purpose": "sd_jwt_vc_issuer"})
