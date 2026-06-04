import importlib
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

from oid4vc import public_routes as test_module
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.issuer_config import IssuerConfiguration
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.public_routes import (
    JWTVerifyResult,
    check_token,
    issue_cred,
    receive_notification,
)

_token_module = importlib.import_module("oid4vc.public_routes.token")
_metadata_module = importlib.import_module("oid4vc.public_routes.metadata")


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

    wallet_id = req.match_info.get("wallet_id")
    async with context.session() as session:
        issuer_config = IssuerConfiguration(configuration_id=wallet_id, new_with_id=True)
        await issuer_config.save(session)

        supported = SupportedCredential(
            format="jwt_vc_json",
            identifier="MyCredential",
            credential_metadata={
                "claims": [{"path": ["name"]}],
            },
        )
        await supported.save(session)

    with patch.object(_metadata_module, "web", autospec=True) as mock_web:
        await test_module.credential_issuer_metadata(req)
        mock_web.json_response.assert_called_once_with(
            {
                "credential_issuer": "http://localhost:8020/tenant/538451fa-11ab-41de-b6e3-7ae3df7356d6",
                "token_endpoint": "http://localhost:8020/tenant/538451fa-11ab-41de-b6e3-7ae3df7356d6/token",
                "credential_endpoint": "http://localhost:8020/tenant/538451fa-11ab-41de-b6e3-7ae3df7356d6/credential",
                "notification_endpoint": "http://localhost:8020/tenant/538451fa-11ab-41de-b6e3-7ae3df7356d6/notification",
                "nonce_endpoint": "http://localhost:8020/tenant/538451fa-11ab-41de-b6e3-7ae3df7356d6/nonce",
                "credential_configurations_supported": {
                    "MyCredential": {
                        "format": "jwt_vc_json",
                        "credential_metadata": {
                            "claims": [{"path": ["name"]}],
                        },
                        "credential_definition": {},
                    }
                },
            }
        )


@pytest.mark.asyncio
async def test_get_token(context: AdminRequestContext, req: web.Request):
    """Test token issuance endpoint."""


@pytest.mark.asyncio
async def test_handle_proof_of_posession(monkeypatch, profile: Profile):
    """Test handling of proof of posession."""
    proof = {
        "proof_type": "jwt",
        "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0oxYzJVaU9pSnphV2NpTENKcmRIa2lPaUpGUXlJc0ltTnlkaUk2SW5ObFkzQXlOVFpyTVNJc0luZ2lPaUpzTWtKbU1GVXlabHA1TFdaMVl6WkJOM3BxYmxwTVJXbFNiM2xzV0VsNWJrMUdOM1JHYUVOd2RqUm5JaXdpZVNJNklrYzBSRlJaUVhGZlEwZHdjVEJ2UkdKQmNVWkxWMWxLTFZoRmRDMUZiVFl6TXpGV2QwcHRjaTFpUkdNaWZRIzAifQ.eyJpYXQiOjE3MDExMjczMTUuMjQ3LCJleHAiOjE3MDExMjc5NzUuMjQ3LCJhdWQiOiJodHRwczovLzEzNTQtMTk4LTkxLTYyLTU4Lm5ncm9rLmlvIiwibm9uY2UiOiIySTF3LUVfNkUtczA3dkFJbzNxOThnIiwiaXNzIjoic3BoZXJlb246c3NpLXdhbGxldCIsImp0aSI6IjdjNzJmODg3LTI4YjQtNDg5Mi04MTUxLWNhZWMxNDRjMzBmMSJ9.XUfMcLMddw1DEqfQvQkk41FTwTmOk-dR3M51PsC76VWn3Ln3KlmPBUEwmFjEEqoEpVIm6kV7K_9svYNc2_ZX4w",
    }
    nonce = "2I1w-E_6E-s07vAIo3q98g"
    # The JWT's aud is an ngrok URL; override the configured endpoint to match
    # so the aud check passes. enable_nonce_endpoint=True exercises DB redemption.
    monkeypatch.setattr(
        _token_module.Config,
        "from_settings",
        lambda settings: MagicMock(
            endpoint="https://1354-198-91-62-58.ngrok.io",
            enable_nonce_endpoint=True,
        ),
    )
    # Create a Nonce record in the DB so DB-based redemption succeeds
    from oid4vc.models.nonce import Nonce
    from acapy_agent.messaging.util import datetime_now, datetime_to_str
    import datetime

    issued_at = datetime_now()
    expires_at = issued_at + datetime.timedelta(seconds=86400)
    nonce_record = Nonce(
        nonce_value=nonce,
        used=False,
        issued_at=datetime_to_str(issued_at),
        expires_at=datetime_to_str(expires_at),
    )
    async with profile.session() as session:
        await nonce_record.save(session, reason="test nonce")

    result = await test_module.handle_proof_of_posession(profile, proof, nonce)
    assert isinstance(result.verified, bool)


# Proof JWT reused from test_handle_proof_of_posession; nonce payload claim is
# "2I1w-E_6E-s07vAIo3q98g" and aud is the ngrok URL set below.
_PROOF = {
    "proof_type": "jwt",
    "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0oxYzJVaU9pSnphV2NpTENKcmRIa2lPaUpGUXlJc0ltTnlkaUk2SW5ObFkzQXlOVFpyTVNJc0luZ2lPaUpzTWtKbU1GVXlabHA1TFdaMVl6WkJOM3BxYmxwTVJXbFNiM2xzV0VsNWJrMUdOM1JHYUVOd2RqUm5JaXdpZVNJNklrYzBSRlJaUVhGZlEwZHdjVEJ2UkdKQmNVWkxWMWxLTFZoRmRDMUZiVFl6TXpGV2QwcHRjaTFpUkdNaWZRIzAifQ.eyJpYXQiOjE3MDExMjczMTUuMjQ3LCJleHAiOjE3MDExMjc5NzUuMjQ3LCJhdWQiOiJodHRwczovLzEzNTQtMTk4LTkxLTYyLTU4Lm5ncm9rLmlvIiwibm9uY2UiOiIySTF3LUVfNkUtczA3dkFJbzNxOThnIiwiaXNzIjoic3BoZXJlb246c3NpLXdhbGxldCIsImp0aSI6IjdjNzJmODg3LTI4YjQtNDg5Mi04MTUxLWNhZWMxNDRjMzBmMSJ9.XUfMcLMddw1DEqfQvQkk41FTwTmOk-dR3M51PsC76VWn3Ln3KlmPBUEwmFjEEqoEpVIm6kV7K_9svYNc2_ZX4w",
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "c_nonce, expect_error",
    [
        ("2I1w-E_6E-s07vAIo3q98g", None),  # match → success
        ("wrong-nonce", "invalid_nonce"),  # mismatch
        (None, "invalid_nonce"),  # missing
    ],
)
async def test_handle_pop_no_nonce_endpoint(
    monkeypatch, profile: Profile, c_nonce, expect_error
):
    """`enable_nonce_endpoint=False` → direct c_nonce comparison (no DB)."""
    monkeypatch.setattr(
        _token_module.Config,
        "from_settings",
        lambda _: MagicMock(
            endpoint="https://1354-198-91-62-58.ngrok.io",
            enable_nonce_endpoint=False,
        ),
    )
    if expect_error:
        with pytest.raises(web.HTTPBadRequest) as exc:
            await test_module.handle_proof_of_posession(profile, _PROOF, c_nonce)
        assert expect_error in exc.value.text
    else:
        result = await test_module.handle_proof_of_posession(profile, _PROOF, c_nonce)
        assert isinstance(result.verified, bool)


@pytest.mark.asyncio
@pytest.mark.parametrize("enable_nonce_endpoint", [True, False])
async def test_get_token_nonce_behavior(monkeypatch, context, enable_nonce_endpoint):
    """Token response carries c_nonce only when Nonce Endpoint is disabled."""
    record = OID4VCIExchangeRecord(
        state=OID4VCIExchangeRecord.STATE_OFFER_CREATED,
        verification_method="did:example:123#k",
        issuer_id="did:example:123",
        supported_cred_id="cred-id",
        credential_subject={"name": "alice"},
        code="pre-auth-code-token-test",
    )
    async with context.profile.session() as session:
        await record.save(session, reason="test")

    monkeypatch.setattr(
        _token_module.Config,
        "from_settings",
        lambda _: MagicMock(
            endpoint="http://localhost:8020",
            enable_nonce_endpoint=enable_nonce_endpoint,
        ),
    )
    monkeypatch.setattr(
        _token_module, "get_first_auth_server", AsyncMock(return_value=None)
    )
    monkeypatch.setattr(
        _token_module,
        "retrieve_or_create_did_jwk",
        AsyncMock(return_value=MagicMock(did="did:jwk:fake")),
    )
    monkeypatch.setattr(_token_module, "jwt_sign", AsyncMock(return_value="tok"))

    request = MagicMock()
    request.__getitem__ = lambda _, k: {"context": context}[k]
    request.post = AsyncMock(
        return_value={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": record.code,
        }
    )

    resp = await _token_module.token(cast(web.Request, request))
    body = json.loads(resp.body)
    async with context.profile.session() as session:
        reloaded = await OID4VCIExchangeRecord.retrieve_by_id(session, record.exchange_id)

    if enable_nonce_endpoint:
        assert "c_nonce" not in body and "c_nonce_expires_in" not in body
        assert reloaded.nonce is None
    else:
        assert body["c_nonce"] and body["c_nonce_expires_in"]
        assert reloaded.nonce == body["c_nonce"]


@pytest.mark.asyncio
async def test_check_token_valid(monkeypatch, context):
    # No IssuerConfiguration in test DB → check_token falls through to jwt_verify
    monkeypatch.setattr(
        _token_module,
        "jwt_verify",
        AsyncMock(
            return_value=JWTVerifyResult(
                headers={}, payload={"exp": 9999999999}, verified=True
            )
        ),
    )

    result = await check_token(context, "Bearer sometoken")
    assert isinstance(result, JWTVerifyResult)
    assert result.verified
    assert result.payload["exp"] == 9999999999


@pytest.mark.asyncio
async def test_check_token_invalid_scheme(context):
    with pytest.raises(Exception):
        await check_token(context, "Token sometoken")


@pytest.mark.asyncio
async def test_check_token_expired(monkeypatch, context):
    # Patch jwt_verify to return an expired token
    monkeypatch.setattr(
        _token_module,
        "jwt_verify",
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
        _token_module,
        "jwt_verify",
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
            "oid4vc.public_routes.notification.OID4VCIExchangeRecord.retrieve_by_notification_id",
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
        "oid4vc.public_routes.credential.OID4VCIExchangeRecord.retrieve_by_refresh_id",
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
        "oid4vc.public_routes.credential.SupportedCredential.retrieve_by_id",
        AsyncMock(return_value=mock_supported),
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
        "proofs": {
            "proof_type": "jwt",
            "jwt": ["header.payload.signature"],
        },
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
    assert "credentials" in data
