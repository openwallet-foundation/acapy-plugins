import importlib
import json
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from acapy_agent.wallet.base import WalletError
from aiohttp import web
from yarl import URL

from oid4vc.auth_providers import AuthContext, AuthServerProvider, BackChannelAuthError
from oid4vc.jose_util import jwk_thumbprint
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential

from ..jose_helpers import dpop_proof, ec_key, public_jwk, sign

# Credential issuer identifier of the test profile (base wallet).
ISSUER_ID = "http://localhost:8020"


def _assertion(credential_issuer=ISSUER_ID):
    """A client assertion naming the tenant; the fake provider doesn't verify it."""
    return sign({}, {"credential_issuer": credential_issuer}, ec_key(), "ES256")


_redeem_module = importlib.import_module("oid4vc.routes.pre_auth_redeem")
_token_module = importlib.import_module("oid4vc.public_routes.token")


class _RedeemingProvider(AuthServerProvider):
    type = "test-redeem"
    supports_redeem = True

    def __init__(self, authenticated=True):
        self.authenticated = authenticated

    async def authenticate_back_channel(self, ctx, params, endpoint_url):
        self.seen = (dict(params), endpoint_url)
        if not self.authenticated:
            raise BackChannelAuthError("nope")


def _request(
    context, body=None, headers=None, path="/oid4vci/pre-auth/redeem", match_info=None
):
    request = MagicMock()
    request.__getitem__ = lambda _, k: {"context": context}[k]
    request.headers = headers or {}
    request.path = path
    request.match_info = match_info or {}
    request.url = URL(f"http://issuer:3001{path}")
    request.post = AsyncMock(return_value=body or {})
    return request


async def _offer(context, pin=None):
    async with context.profile.session() as session:
        supported = SupportedCredential(format="jwt_vc_json", identifier="MyCred")
        await supported.save(session)
        record = OID4VCIExchangeRecord(
            state=OID4VCIExchangeRecord.STATE_OFFER_CREATED,
            verification_method="did:example:123#k",
            issuer_id="did:example:123",
            supported_cred_id=supported.supported_cred_id,
            credential_subject={"name": "alice"},
            code="code-xyz",
            pin=pin,
        )
        await record.save(session)
    return record


def _use_provider(monkeypatch, context, provider):
    monkeypatch.setattr(
        _redeem_module,
        "resolve_auth_provider",
        AsyncMock(return_value=(provider, AuthContext(context.profile, MagicMock(), {}))),
    )


@pytest.mark.asyncio
async def test_redeem_success(monkeypatch, context):
    record = await _offer(context, pin="4321")
    provider = _RedeemingProvider()
    _use_provider(monkeypatch, context, provider)
    assertion = _assertion()
    resp = await _redeem_module.redeem_pre_auth_code_route(
        cast(
            web.Request,
            _request(
                context,
                {
                    "pre_authorized_code": "code-xyz",
                    "tx_code": "4321",
                    "wallet_client_id": "w",
                    "client_assertion": assertion,
                },
            ),
        )
    )
    body = json.loads(resp.body)
    assert resp.status == 200
    assert body["refresh_id"] == record.refresh_id
    assert body["credential_configuration_ids"] == ["MyCred"]
    # Credentials and the endpoint URL are handed to the provider for auth
    params, endpoint_url = provider.seen
    assert params["client_assertion"] == assertion
    assert endpoint_url == "http://issuer:3001/oid4vci/pre-auth/redeem"

    # Single use
    resp = await _redeem_module.redeem_pre_auth_code_route(
        cast(
            web.Request,
            _request(
                context,
                {
                    "pre_authorized_code": "code-xyz",
                    "tx_code": "4321",
                    "credential_issuer": ISSUER_ID,
                },
            ),
        )
    )
    assert resp.status == 400
    assert json.loads(resp.body)["error"] == "invalid_grant"


async def _redeem(context, **params):
    return await _redeem_module.redeem_pre_auth_code_route(
        cast(
            web.Request,
            _request(
                context,
                {
                    "pre_authorized_code": "code-xyz",
                    "client_assertion": _assertion(),
                    **params,
                },
            ),
        )
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "requested, error",
    [
        ('["Other"]', "invalid_authorization_details"),
        ('["MyCred", "Other"]', "invalid_authorization_details"),
        ("not json", "invalid_request"),
        ("[]", "invalid_request"),
        ('"MyCred"', "invalid_request"),
    ],
)
async def test_redeem_rejects_other_configurations_without_consuming_the_code(
    monkeypatch, context, requested, error
):
    await _offer(context)
    _use_provider(monkeypatch, context, _RedeemingProvider())
    resp = await _redeem(context, credential_configuration_ids=requested)
    assert resp.status == 400
    assert json.loads(resp.body)["error"] == error
    async with context.profile.session() as session:
        rec = await OID4VCIExchangeRecord.retrieve_by_code(session, "code-xyz")
    assert rec.code_redeemed_at is None

    # The code still works for the configuration the offer grants.
    resp = await _redeem(context, credential_configuration_ids='["MyCred"]')
    assert resp.status == 200
    assert json.loads(resp.body)["credential_configuration_ids"] == ["MyCred"]


@pytest.mark.asyncio
async def test_redeem_unauthenticated(monkeypatch, context):
    await _offer(context)
    _use_provider(monkeypatch, context, _RedeemingProvider(authenticated=False))
    resp = await _redeem_module.redeem_pre_auth_code_route(
        cast(
            web.Request,
            _request(
                context,
                {"pre_authorized_code": "code-xyz", "credential_issuer": ISSUER_ID},
            ),
        )
    )
    assert resp.status == 401
    # The code was not consumed
    async with context.profile.session() as session:
        rec = await OID4VCIExchangeRecord.retrieve_by_code(session, "code-xyz")
    assert rec.code_redeemed_at is None


async def _redeem_status(context, params) -> int:
    resp = await _redeem_module.redeem_pre_auth_code_route(
        cast(web.Request, _request(context, params))
    )
    assert json.loads(resp.body)["error"] in ("invalid_client", "invalid_grant")
    return resp.status


@pytest.mark.asyncio
async def test_redeem_not_available_for_builtin(context):
    # No authorization server configured -> built-in provider -> no redeem
    params = {"pre_authorized_code": "x", "credential_issuer": ISSUER_ID}
    assert await _redeem_status(context, params) == 401


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    [
        # no credential issuer named
        {"pre_authorized_code": "x"},
        # an issuer this agent doesn't serve
        {"pre_authorized_code": "x", "credential_issuer": "https://other.example"},
        # a tenant, but multitenancy is off
        {"pre_authorized_code": "x", "credential_issuer": f"{ISSUER_ID}/tenant/abc"},
        # undecodable assertion
        {"pre_authorized_code": "x", "client_assertion": "not-a-jwt"},
        # form parameter and signed claim disagree
        {
            "pre_authorized_code": "x",
            "credential_issuer": ISSUER_ID,
            "client_assertion": _assertion(f"{ISSUER_ID}/tenant/abc"),
        },
    ],
)
async def test_redeem_tenant_resolution_rejected(monkeypatch, context, params):
    provider = _RedeemingProvider()
    _use_provider(monkeypatch, context, provider)
    assert await _redeem_status(context, params) == 401
    assert not hasattr(provider, "seen")  # never reached authentication


@pytest.mark.asyncio
async def test_builtin_token_binds_dpop(monkeypatch, context):
    record = await _offer(context)
    sign = AsyncMock(return_value="tok")
    monkeypatch.setattr(_token_module, "jwt_sign", sign)
    monkeypatch.setattr(
        _token_module,
        "retrieve_or_create_did_jwk",
        AsyncMock(return_value=MagicMock(did="did:jwk:fake")),
    )
    key = ec_key()
    request = _request(
        context,
        headers={"DPoP": dpop_proof(key, htu="http://localhost:8020/token")},
        path="/token",
    )
    request.post = AsyncMock(
        return_value={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": record.code,
        }
    )
    resp = await _token_module.token(cast(web.Request, request))
    body = json.loads(resp.body)
    assert resp.status == 200
    assert body["token_type"] == "DPoP"
    payload = sign.call_args.kwargs["payload"]
    assert payload["cnf"] == {"jkt": jwk_thumbprint(public_jwk(key))}


@pytest.mark.asyncio
async def test_builtin_token_invalid_dpop_keeps_code(monkeypatch, context):
    record = await _offer(context)
    request = _request(
        context,
        headers={"DPoP": dpop_proof(ec_key(), htu="https://elsewhere.example/token")},
        path="/token",
    )
    request.post = AsyncMock(
        return_value={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": record.code,
        }
    )
    resp = await _token_module.token(cast(web.Request, request))
    assert resp.status == 400
    assert json.loads(resp.body)["error"] == "invalid_dpop_proof"
    async with context.profile.session() as session:
        rec = await OID4VCIExchangeRecord.retrieve_by_code(session, record.code)
    assert rec.code_redeemed_at is None


@pytest.mark.asyncio
async def test_builtin_token_signing_failure_keeps_code(monkeypatch, context):
    record = await _offer(context)
    monkeypatch.setattr(
        _token_module,
        "retrieve_or_create_did_jwk",
        AsyncMock(return_value=MagicMock(did="did:jwk:fake")),
    )
    monkeypatch.setattr(
        _token_module, "jwt_sign", AsyncMock(side_effect=WalletError("x"))
    )
    request = _request(context, path="/token")
    request.post = AsyncMock(
        return_value={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": record.code,
        }
    )
    resp = await _token_module.token(cast(web.Request, request))
    assert resp.status == 500
    assert json.loads(resp.body)["error"] == "server_error"
    async with context.profile.session() as session:
        rec = await OID4VCIExchangeRecord.retrieve_by_code(session, record.code)
    assert rec.code_redeemed_at is None and rec.token is None

    # The same code is still redeemable once signing works.
    monkeypatch.setattr(_token_module, "jwt_sign", AsyncMock(return_value="tok"))
    resp = await _token_module.token(cast(web.Request, request))
    assert resp.status == 200
    async with context.profile.session() as session:
        rec = await OID4VCIExchangeRecord.retrieve_by_code(session, record.code)
    assert rec.token == "tok" and rec.code_redeemed_at


@pytest.mark.asyncio
async def test_redeem_resolves_tenant_from_credential_issuer(context):
    from acapy_agent.multitenant.base import BaseMultitenantManager
    from acapy_agent.wallet.models.wallet_record import WalletRecord

    tenant_profile = MagicMock()
    manager = MagicMock(spec=BaseMultitenantManager)
    manager.get_wallet_profile = AsyncMock(return_value=tenant_profile)
    context.profile.context.injector.bind_instance(BaseMultitenantManager, manager)
    async with context.profile.session() as session:
        managed = WalletRecord(key_management_mode=WalletRecord.MODE_MANAGED, settings={})
        await managed.save(session)
        unmanaged = WalletRecord(
            key_management_mode=WalletRecord.MODE_UNMANAGED, settings={}
        )
        await unmanaged.save(session)

    profile = await _redeem_module._target_profile(
        context, f"{ISSUER_ID}/tenant/{managed.wallet_id}"
    )
    assert profile is tenant_profile
    assert manager.get_wallet_profile.call_args.args[1].wallet_id == managed.wallet_id

    # Base wallet, unknown or unmanaged tenants
    assert await _redeem_module._target_profile(context, ISSUER_ID) is context.profile
    for issuer in (
        f"{ISSUER_ID}/tenant/{unmanaged.wallet_id}",
        f"{ISSUER_ID}/tenant/does-not-exist",
        f"{ISSUER_ID}/tenant/{managed.wallet_id}/extra",
    ):
        with pytest.raises(_redeem_module._UnknownTenant):
            await _redeem_module._target_profile(context, issuer)
