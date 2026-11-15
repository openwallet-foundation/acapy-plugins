import json

import pytest
from aiohttp import web
from aries_askar import Key, KeyAlg

from oid4vc.models.wallet_provider import WalletProvider
from oid4vc.routes import wallet_provider as test_module

JWK = {**json.loads(Key.generate(KeyAlg.P256).get_jwk_public()), "kid": "key-1"}


@pytest.fixture
def make_request(context):
    class Request:
        def __init__(self, body=None, match_info=None, method="POST"):
            self._body = body or {}
            self.match_info = match_info or {}
            self.method = method
            self.headers = {}
            self.path = "/oid4vci/wallet-providers"

        async def json(self):
            return self._body

        def __getitem__(self, key):
            if key == "context":
                return context
            raise KeyError(key)

    return Request


async def _create(make_request, **body):
    resp = await test_module.wallet_provider_create(
        make_request(
            {"iss": "https://wallet.example.com", "jwks": {"keys": [JWK]}, **body}
        )
    )
    return json.loads(resp.text)


async def test_crud(make_request, profile):
    created = await _create(make_request, name="Example")
    provider_id = created["wallet_provider_id"]
    assert created["active"] is True

    listed = json.loads(
        (await test_module.wallet_provider_list(make_request(method="GET"))).text
    )
    assert [p["wallet_provider_id"] for p in listed["results"]] == [provider_id]

    got = json.loads(
        (
            await test_module.wallet_provider_get(
                make_request(method="GET", match_info={"wallet_provider_id": provider_id})
            )
        ).text
    )
    assert got["iss"] == "https://wallet.example.com"

    updated = json.loads(
        (
            await test_module.wallet_provider_update(
                make_request(
                    {"active": False},
                    match_info={"wallet_provider_id": provider_id},
                    method="PATCH",
                )
            )
        ).text
    )
    assert updated["active"] is False
    assert updated["jwks"] == {"keys": [JWK]}
    async with profile.session() as session:
        assert not await WalletProvider.query(session, {"active": "True"})

    await test_module.wallet_provider_delete(
        make_request(method="DELETE", match_info={"wallet_provider_id": provider_id})
    )
    with pytest.raises(web.HTTPNotFound):
        await test_module.wallet_provider_get(
            make_request(method="GET", match_info={"wallet_provider_id": provider_id})
        )


@pytest.mark.parametrize(
    "body",
    [
        {"iss": ""},
        {"jwks": None},
        {"jwks": None, "jwks_uri": "http://wallet.example.com/jwks.json"},
        {"jwks": {"keys": []}},
        {"jwks": {"keys": [{k: v for k, v in JWK.items() if k != "kid"}]}},
        {"jwks_uri": "https://wallet.example.com/jwks.json"},
        {"jwks": {"keys": [{"kid": "rsa", "kty": "RSA", "n": "AQAB", "e": "AQAB"}]}},
        {"jwks": {"keys": [{**JWK, "use": "enc"}]}},
        {"jwks": {"keys": [{**JWK, "alg": "ES384"}]}},
    ],
)
async def test_create_rejects_invalid(make_request, body):
    with pytest.raises(web.HTTPBadRequest):
        await _create(make_request, **body)


@pytest.mark.parametrize(
    "jwk",
    [
        {**JWK, "use": "sig", "alg": "ES256"},
        {
            **json.loads(Key.generate(KeyAlg.ED25519).get_jwk_public()),
            "kid": "ed",
            "alg": "EdDSA",
        },
    ],
)
async def test_create_accepts_signing_members(make_request, jwk):
    created = await _create(make_request, jwks={"keys": [jwk]})
    assert created["jwks"] == {"keys": [jwk]}


async def test_iss_unique(make_request):
    first = await _create(make_request)
    await _create(make_request, iss="https://other.example.com")
    with pytest.raises(web.HTTPBadRequest):
        await _create(make_request)
    with pytest.raises(web.HTTPBadRequest):
        await test_module.wallet_provider_update(
            make_request(
                {"iss": "https://other.example.com"},
                match_info={"wallet_provider_id": first["wallet_provider_id"]},
                method="PATCH",
            )
        )
    # Updating a provider without changing its iss is allowed
    await test_module.wallet_provider_update(
        make_request(
            {"name": "renamed"},
            match_info={"wallet_provider_id": first["wallet_provider_id"]},
            method="PATCH",
        )
    )


async def test_update_rejects_removing_all_keys(make_request):
    created = await _create(make_request)
    with pytest.raises(web.HTTPBadRequest):
        await test_module.wallet_provider_update(
            make_request(
                {"jwks": None},
                match_info={"wallet_provider_id": created["wallet_provider_id"]},
                method="PATCH",
            )
        )


async def test_update_switches_key_source(make_request, profile):
    created = await _create(make_request)
    match_info = {"wallet_provider_id": created["wallet_provider_id"]}
    uri = "https://wallet.example.com/jwks.json"
    with pytest.raises(web.HTTPBadRequest):
        await test_module.wallet_provider_update(
            make_request({"jwks_uri": uri}, match_info=match_info, method="PATCH")
        )
    async with profile.session() as session:
        stored = await WalletProvider.retrieve_by_id(
            session, match_info["wallet_provider_id"]
        )
    assert (stored.jwks, stored.jwks_uri) == ({"keys": [JWK]}, None)

    resp = await test_module.wallet_provider_update(
        make_request(
            {"jwks_uri": uri, "jwks": None}, match_info=match_info, method="PATCH"
        )
    )
    updated = json.loads(resp.text)
    assert (updated.get("jwks"), updated["jwks_uri"]) == (None, uri)


async def test_update_missing(make_request):
    with pytest.raises(web.HTTPNotFound):
        await test_module.wallet_provider_update(
            make_request({}, match_info={"wallet_provider_id": "missing"}, method="PATCH")
        )
