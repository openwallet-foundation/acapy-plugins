import json
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.did_method import KEY
from acapy_agent.wallet.key_type import ED25519
from aiohttp import web

from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.public_routes import (
    JWTVerifyResult,
    check_token,
    credential_issuer_metadata,
    handle_proof_of_posession,
    issue_cred,
    receive_notification,
)


@pytest.fixture
def req(context: AdminRequestContext):
    """Test web.Request."""
    items = {
        "context": context,
        "wallet_id": "538451fa-11ab-41de-b6e3-7ae3df7356d6",
    }
    mock = MagicMock()
    mock.__getitem__ = lambda _, k: items[k]
    match_info = {"wallet_id": items["wallet_id"]}
    mock.match_info = match_info
    yield mock


@pytest.mark.asyncio
async def test_issuer_metadata(context: AdminRequestContext, req: web.Request):
    """Test issuer metadata endpoint."""
    supported = SupportedCredential(
        format="jwt_vc_json",
        identifier="MyCredential",
        format_data={
            "credentialSubject": {"name": "alice"},
        },
    )

    async with context.session() as session:
        await supported.save(session)

    with patch("aiohttp.web.json_response") as mock_json_response:
        await credential_issuer_metadata(req)
        wallet_id = req.match_info.get(
            "wallet_id",
        )
        mock_json_response.assert_called_once_with(
            {
                "credential_issuer": f"http://localhost:8020/tenant/{wallet_id}",
                "authorization_servers": ["http://localhost:9001"],
                "credential_endpoint": f"http://localhost:8020/tenant/{wallet_id}/credential",
                "notification_endpoint": f"http://localhost:8020/tenant/{wallet_id}/notification",
                "nonce_endpoint": f"http://localhost:8020/tenant/{wallet_id}/nonce",
                "credential_configurations_supported": {
                    "MyCredential": {
                        "format": "jwt_vc_json",
                        "credential_definition": {"credentialSubject": {"name": "alice"}},
                    }
                },
            }
        )


@pytest.mark.asyncio
async def test_issuer_metadata_no_auth_server():
    """Credential issuer metadata without external auth server.

    When no auth_server_url is configured, the response must omit
    ``authorization_servers`` but include ``token_endpoint`` directly.
    Some wallets (e.g. waltid) read token_endpoint from the credential issuer
    metadata rather than performing AS discovery.
    """
    from acapy_agent.resolver.did_resolver import DIDResolver
    from acapy_agent.utils.testing import create_test_profile
    from acapy_agent.wallet.default_verification_key_strategy import (
        BaseVerificationKeyStrategy,
        DefaultVerificationKeyStrategy,
    )

    from jwt_vc_json import JwtVcJsonCredProcessor
    from oid4vc.cred_processor import CredProcessors
    from oid4vc.jwk_resolver import JwkResolver
    from sd_jwt_vc.cred_processor import SdJwtCredIssueProcessor

    no_auth_settings = {
        "admin.admin_insecure_mode": True,
        "wallet.id": "538451fa-11ab-41de-b6e3-7ae3df7356d6",
        "plugin_config": {
            "oid4vci": {
                "host": "localhost",
                "port": 8020,
                "endpoint": "http://localhost:8020",
            }
        },
    }
    processors = CredProcessors(
        {"jwt_vc_json": JwtVcJsonCredProcessor()},
        {"sd_jwt_vc": SdJwtCredIssueProcessor()},
    )
    profile = await create_test_profile(no_auth_settings)
    profile.context.injector.bind_instance(DIDResolver, DIDResolver([JwkResolver()]))
    profile.context.injector.bind_instance(
        BaseVerificationKeyStrategy, DefaultVerificationKeyStrategy()
    )
    profile.context.injector.bind_instance(CredProcessors, processors)

    ctx = AdminRequestContext(profile)

    supported = SupportedCredential(
        format="jwt_vc_json",
        identifier="TestCred",
        format_data={"credentialSubject": {"name": "bob"}},
    )
    async with ctx.session() as session:
        await supported.save(session)

    items = {"context": ctx, "wallet_id": "538451fa-11ab-41de-b6e3-7ae3df7356d6"}
    mock_req = MagicMock()
    mock_req.__getitem__ = lambda _, k: items[k]
    mock_req.match_info = {"wallet_id": items["wallet_id"]}
    mock_req.headers = {}

    with patch("aiohttp.web.json_response") as mock_json_response:
        await credential_issuer_metadata(mock_req)
        response_data = mock_json_response.call_args[0][0]
        wallet_id = items["wallet_id"]
        assert "authorization_servers" not in response_data
        assert (
            response_data["token_endpoint"]
            == f"http://localhost:8020/tenant/{wallet_id}/token"
        )
        assert (
            response_data["credential_issuer"]
            == f"http://localhost:8020/tenant/{wallet_id}"
        )
        assert (
            response_data["credential_endpoint"]
            == f"http://localhost:8020/tenant/{wallet_id}/credential"
        )
        assert (
            response_data["nonce_endpoint"]
            == f"http://localhost:8020/tenant/{wallet_id}/nonce"
        )


@pytest.mark.asyncio
async def test_get_token(context: AdminRequestContext, req: web.Request):
    """Test token issuance endpoint."""


@pytest.mark.asyncio
async def test_handle_proof_of_posession(profile: Profile):
    """Test handling of proof of possession with a self-contained synthetic JWT.

    Generates a fresh EC keypair inline, builds and signs a proper
    openid4vci-proof+jwt, and verifies it through handle_proof_of_posession.
    No captured tokens or external URLs are used.
    """
    import base64
    import json
    import time

    from aries_askar import Key, KeyAlg

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    nonce = "test-nonce-synthetic-1234"
    # Must match `endpoint` in conftest.py settings so the aud check passes.
    issuer_endpoint = "http://localhost:8020"

    # Generate a fresh P-256 key pair for the holder.
    key = Key.generate(KeyAlg.P256)
    public_jwk = json.loads(key.get_jwk_public())

    # Build a valid openid4vci-proof+jwt embedding the public JWK in the header
    # so handle_proof_of_posession can resolve it without DID lookup.
    header = {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": public_jwk}
    payload = {
        "iat": int(time.time()),
        "exp": int(time.time()) + 600,
        "aud": issuer_endpoint,
        "nonce": nonce,
    }
    h_enc = _b64url(json.dumps(header).encode())
    p_enc = _b64url(json.dumps(payload).encode())
    sig = key.sign_message(f"{h_enc}.{p_enc}".encode(), sig_type="ES256")
    s_enc = _b64url(sig)

    proof = {"proof_type": "jwt", "jwt": f"{h_enc}.{p_enc}.{s_enc}"}

    result = await handle_proof_of_posession(profile, proof, nonce)
    assert result.verified is True
    assert result.holder_jwk == public_jwk


@pytest.mark.asyncio
async def test_check_token_valid(monkeypatch, context):
    # Patch get_auth_header to return a dummy header
    monkeypatch.setattr(
        "oid4vc.utils.get_auth_header",
        AsyncMock(return_value="Bearer dummyheader"),
    )

    # Patch AppResources.get_http_client to return a mock client
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.json = AsyncMock(
        return_value={"active": True, "exp": 9999999999, "sub": "subject"}
    )
    mock_client.post = AsyncMock(return_value=mock_response)
    monkeypatch.setattr(
        "oid4vc.app_resources.AppResources.get_http_client", lambda: mock_client
    )

    # Call check_token with a valid bearer token
    result = await check_token(context, "Bearer sometoken")
    assert isinstance(result, JWTVerifyResult)
    assert result.verified
    assert result.payload["active"] is True


@pytest.mark.asyncio
async def test_check_token_invalid_scheme(context):
    with pytest.raises(Exception):
        await check_token(context, "Token sometoken")


@pytest.mark.asyncio
async def test_check_token_expired(monkeypatch, context):
    # Patch jwt_verify to return an expired token
    monkeypatch.setattr(
        "oid4vc.jwt.jwt_verify",
        AsyncMock(
            return_value=JWTVerifyResult(headers={}, payload={"exp": 1}, verified=True)
        ),
    )
    with pytest.raises(Exception):
        await check_token(context, "Bearer sometoken")


@pytest.mark.asyncio
async def test_check_token_invalid_token(monkeypatch, context):
    # Patch jwt_verify to return not verified
    monkeypatch.setattr(
        "oid4vc.jwt.jwt_verify",
        AsyncMock(
            return_value=JWTVerifyResult(
                headers={}, payload={"exp": 9999999999}, verified=False
            )
        ),
    )
    with pytest.raises(Exception):
        await check_token(context, "Bearer sometoken")


@pytest.mark.asyncio
async def test_receive_notification(context):
    # Prepare request body
    body = {
        "notification_id": "notif-123",
        "event": "credential_accepted",
        "event_description": "Accepted!",
    }

    # Create a mock request
    class DummyRequest:
        def __init__(self):
            self.headers = {"Authorization": "Bearer validtoken"}
            self._json = body

        async def json(self):
            return self._json

        def __getitem__(self, key):
            if key == "context":
                return context
            raise KeyError(key)

    request = DummyRequest()

    # Patch check_token to always return True
    with patch(
        "oid4vc.public_routes.notification.check_token", AsyncMock(return_value=True)
    ):
        # Patch OID4VCIExchangeRecord.retrieve_by_notification_id to return a mock record
        mock_record = AsyncMock()
        mock_record.state = None
        mock_record.notification_event = None
        mock_record.save = AsyncMock()
        with patch(
            "oid4vc.models.exchange.OID4VCIExchangeRecord.retrieve_by_notification_id",
            AsyncMock(return_value=mock_record),
        ):
            # Patch context.profile.session to return an async context manager
            class DummySession:
                async def __aenter__(self):
                    return self

                async def __aexit__(self, exc_type, exc, tb):
                    pass

            context.profile.session = lambda: DummySession()

            resp = await receive_notification(cast(web.Request, request))
            assert isinstance(resp, web.Response)
            assert resp.status == 204


@pytest.mark.asyncio
async def test_issue_cred(monkeypatch, context, dummy_request):
    # Patch check_token to return a mock JWTVerifyResult
    mock_token_result = MagicMock()
    mock_token_result.payload = {
        "sub": "refresh_id",
        "c_nonce": "test_nonce",
    }
    monkeypatch.setattr(
        "oid4vc.public_routes.credential.check_token",
        AsyncMock(return_value=mock_token_result),
    )

    # Patch OID4VCIExchangeRecord.retrieve_by_refresh_id
    mock_ex_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_ex_record.state = OID4VCIExchangeRecord.STATE_OFFER_CREATED
    mock_ex_record.issuer_id = "did:key:issuer"
    mock_ex_record.supported_cred_id = "cred_id"
    mock_ex_record.nonce = "test_nonce"
    mock_ex_record.format = "jwt_vc_json"
    mock_ex_record.refresh_id = "refresh_id"
    mock_ex_record.notification_id = "notif_id"
    mock_ex_record.credential_subject = {"name": "alice"}
    mock_ex_record.verification_method = "did:example:123#key-1"
    mock_ex_record.save = AsyncMock()
    monkeypatch.setattr(
        "oid4vc.models.exchange.OID4VCIExchangeRecord.retrieve_by_refresh_id",
        AsyncMock(return_value=mock_ex_record),
    )
    # Patch wallet.get_local_did to return a dummy DIDInfo
    dummy_did_info = DIDInfo(
        method=KEY,
        key_type=ED25519,
        did="did:example:123",
        verkey="dummyverkey",
        metadata={},
    )
    monkeypatch.setattr(
        "acapy_agent.wallet.askar.AskarWallet.get_local_did",
        AsyncMock(return_value=dummy_did_info),
    )
    # Patch wallet.sign_message to return a dummy signature
    monkeypatch.setattr(
        "acapy_agent.wallet.askar.AskarWallet.sign_message",
        AsyncMock(return_value=b"dummy_signature"),
    )
    # Patch SupportedCredential.retrieve_by_id
    mock_supported = MagicMock(spec=SupportedCredential)
    mock_supported.format = "jwt_vc_json"
    mock_supported.identifier = "cred_id"
    mock_supported.format_data = {"some": "data"}
    mock_supported.to_issuer_metadata = MagicMock(return_value={})
    mock_supported.vc_additional_data = {}
    monkeypatch.setattr(
        "oid4vc.models.supported_cred.SupportedCredential.retrieve_by_id",
        AsyncMock(return_value=mock_supported),
    )

    # Patch signing to avoid depending on wallet implementation details
    monkeypatch.setattr(
        "jwt_vc_json.cred_processor.jwt_sign",
        AsyncMock(return_value="header.payload.signature"),
    )

    # Patch handle_proof_of_posession to return a verified PopResult
    mock_pop = MagicMock()
    mock_pop.verified = True
    mock_pop.holder_kid = "did:example:123#key-1"
    monkeypatch.setattr(
        "oid4vc.public_routes.credential.handle_proof_of_posession",
        AsyncMock(return_value=mock_pop),
    )

    # Patch session context manager
    class DummySession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

    context.session = MagicMock(return_value=DummySession())

    # Prepare dummy request
    body = {
        "format": "jwt_vc_json",
        "type": ["VerifiableCredential"],
        "proof": {"jwt": "header.payload.signature"},
    }
    req = dummy_request(json_data=body)

    # Patch request.headers
    req.headers = {"Authorization": "Bearer testtoken"}

    # Call the endpoint
    resp = await issue_cred(req)
    assert resp.status == 200
    assert resp.text is not None

    # Parse the JSON response body
    data = json.loads(resp.text)
    # OID4VCI 1.0: response uses `credentials` array, not deprecated `format`/`credential`
    assert "credentials" in data
    assert len(data["credentials"]) == 1
    assert "credential" in data["credentials"][0]
