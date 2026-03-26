"""Unit tests for JwtVcJsonCredProcessor.

Key behaviour being tested:

1. **Happy path (holder_kid / holder_jwk)** – ``issue()`` builds a JWT-VC
   payload and returns a signed JWS.

2. **StatusHandler integration** – when a ``StatusHandler`` is injected,
   ``assign_status_entries`` is awaited and the ``credentialStatus`` claim
   is embedded in the VC payload before signing.

3. **Status-assignment ordering** – the status entry is assigned *after* the
   subject is successfully extracted from the POP.  If the POP is invalid
   (neither ``holder_kid`` starting with ``"did:"`` nor ``holder_jwk``), a
   ``ValueError`` is raised *before* any call to ``assign_status_entries``.
   This means that an invalid POP does **not** consume a status-list slot but,
   conversely, leaves no ``StatusListCred`` record – so PATCH
   ``/status-list/defs/{id}/creds/{exchange_id}`` would return 404 for that
   exchange.  The integration tests reproduce this end-to-end; these unit tests
   document and guard the boundary at the processor level.

   See also: ``oid4vc/integration/tests/debug/test_status_list_steps.py``
   (step 5) and ``test_credo_revocation.py`` for the integration-level story.

4. **No StatusHandler** – when no ``StatusHandler`` is registered in the
   context, ``credentialStatus`` is absent from the VC.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from acapy_agent.admin.request_context import AdminRequestContext

from jwt_vc_json.cred_processor import JwtVcJsonCredProcessor
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult
from oid4vc.status_handler import StatusHandler

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_JWS = "eyJhbGciOiJFZERTQSJ9.e30.fake_sig"

_SAMPLE_CREDENTIAL_STATUS = {
    "id": "https://example.com/status-list/1#42",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "42",
    "statusListCredential": "https://example.com/status-list/1",
}


def _make_mock_status_handler(credential_status=None):
    """Return a mock StatusHandler whose assign_status_entries is an AsyncMock."""
    handler = MagicMock(spec=StatusHandler)
    handler.assign_status_entries = AsyncMock(
        return_value=credential_status or _SAMPLE_CREDENTIAL_STATUS
    )
    return handler


def _make_context_with_status_handler(status_handler=None):
    """Return a mock AdminRequestContext with an optional StatusHandler bound."""
    context = MagicMock(spec=AdminRequestContext)
    context.inject_or.return_value = status_handler
    return context


def _make_jwk_pop():
    """Return a PopResult that uses JWK holder binding (no holder_kid)."""
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    }
    pop = MagicMock(spec=PopResult)
    pop.holder_kid = None
    pop.holder_jwk = jwk
    return pop


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCredentialProcessor:
    """Tests for JwtVcJsonCredProcessor.issue()."""

    # ------------------------------------------------------------------
    # Existing smoke test – kept and fixed to actually await the coroutine
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_issue_credential_returns_jws(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
    ):
        """issue() returns a JWS string when pop contains a did: kid.

        The test mocks both jwt_sign (to avoid needing a real DID/key) and the
        AdminRequestContext (no status handler).
        """
        context = _make_context_with_status_handler(None)

        with patch(
            "jwt_vc_json.cred_processor.jwt_sign", new_callable=AsyncMock
        ) as mock_sign:
            mock_sign.return_value = _FAKE_JWS
            cred_processor = JwtVcJsonCredProcessor()
            jws = await cred_processor.issue(body, supported, ex_record, pop, context)

        assert jws == _FAKE_JWS

    # ------------------------------------------------------------------
    # StatusHandler – happy paths
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_issue_with_status_handler_embeds_credential_status(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
    ):
        """When a StatusHandler is present, credentialStatus is embedded in the VC.

        Guards the regression path for:
          PATCH /status-list/defs/{def_id}/creds/{exchange_id} → 200

        (If assign_status_entries is never called, the PATCH returns 404.)
        """
        mock_handler = _make_mock_status_handler()
        context = _make_context_with_status_handler(mock_handler)

        captured_payload: dict = {}

        async def _mock_sign(profile, headers, payload, **kwargs):
            captured_payload.update(payload)
            return _FAKE_JWS

        with patch("jwt_vc_json.cred_processor.jwt_sign", side_effect=_mock_sign):
            cred_processor = JwtVcJsonCredProcessor()
            jws = await cred_processor.issue(body, supported, ex_record, pop, context)

        assert jws == _FAKE_JWS

        # assign_status_entries MUST have been called with the exchange_id so
        # that the StatusListCred record exists for later PATCH revocation.
        mock_handler.assign_status_entries.assert_awaited_once()
        call_args = mock_handler.assign_status_entries.call_args
        assert call_args.args[2] == ex_record.exchange_id, (
            "assign_status_entries must receive exchange_id as credential_id "
            "so that PATCH /status-list/defs/{id}/creds/{exchange_id} can find it."
        )

        # The credentialStatus claim must be embedded in the VC payload.
        assert "credentialStatus" in captured_payload.get("vc", {}), (
            "credentialStatus missing from VC payload; the PATCH endpoint "
            "will return 404 after issuance."
        )
        assert captured_payload["vc"]["credentialStatus"] == _SAMPLE_CREDENTIAL_STATUS

    @pytest.mark.asyncio
    async def test_issue_with_jwk_pop_assigns_status(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
    ):
        """JWK holder binding also triggers status assignment.

        Wallets like Credo can send a JWK-bound POP (no holder_kid DID).
        The processor should derive a did:jwk subject and still call
        assign_status_entries so that revocation works.
        """
        pop = _make_jwk_pop()
        mock_handler = _make_mock_status_handler()
        context = _make_context_with_status_handler(mock_handler)

        with patch(
            "jwt_vc_json.cred_processor.jwt_sign", new_callable=AsyncMock
        ) as mock_sign:
            mock_sign.return_value = _FAKE_JWS
            cred_processor = JwtVcJsonCredProcessor()
            jws = await cred_processor.issue(body, supported, ex_record, pop, context)

        assert jws == _FAKE_JWS
        mock_handler.assign_status_entries.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_issue_without_status_handler_omits_credential_status(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
    ):
        """When no StatusHandler is registered, credentialStatus is absent."""
        context = _make_context_with_status_handler(None)

        captured_payload: dict = {}

        async def _mock_sign(profile, headers, payload, **kwargs):
            captured_payload.update(payload)
            return _FAKE_JWS

        with patch("jwt_vc_json.cred_processor.jwt_sign", side_effect=_mock_sign):
            cred_processor = JwtVcJsonCredProcessor()
            await cred_processor.issue(body, supported, ex_record, pop, context)

        assert "credentialStatus" not in captured_payload.get("vc", {})

    # ------------------------------------------------------------------
    # StatusHandler – ordering / failure path
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_invalid_pop_raises_before_status_assignment(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
    ):
        """When the POP has no usable holder identifier, ValueError fires BEFORE
        assign_status_entries is called.

        This means an exchange with an invalid POP does NOT consume a
        status-list slot (correct), but it also means that if a subsequent
        PATCH /status-list/defs/{id}/creds/{exchange_id} is attempted for
        that exchange it will return 404 (no StatusListCred record exists).

        The integration-level guard is in test_status_list_steps.py step 5.
        """
        pop = MagicMock(spec=PopResult)
        pop.holder_kid = None  # no DID kid
        pop.holder_jwk = None  # no JWK binding → ValueError expected

        mock_handler = _make_mock_status_handler()
        context = _make_context_with_status_handler(mock_handler)

        cred_processor = JwtVcJsonCredProcessor()

        with pytest.raises(ValueError, match="Unsupported pop holder value"):
            await cred_processor.issue(body, supported, ex_record, pop, context)

        # Crucially, no status slot must have been consumed.
        mock_handler.assign_status_entries.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_holder_kid_without_did_prefix_raises_before_status_assignment(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
    ):
        """A holder_kid that does NOT start with 'did:' also triggers the ValueError.

        Some wallets may send a bare key thumbprint as the kid.  This path is
        currently unsupported and raises before any status assignment.
        """
        pop = MagicMock(spec=PopResult)
        pop.holder_kid = "not-a-did-key"  # present but not a DID
        pop.holder_jwk = None

        mock_handler = _make_mock_status_handler()
        context = _make_context_with_status_handler(mock_handler)

        cred_processor = JwtVcJsonCredProcessor()

        with pytest.raises(ValueError, match="Unsupported pop holder value"):
            await cred_processor.issue(body, supported, ex_record, pop, context)

        mock_handler.assign_status_entries.assert_not_awaited()

    # ------------------------------------------------------------------
    # Payload structure
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_issue_payload_contains_required_jwt_claims(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
    ):
        """The JWT payload includes iss, sub, nbf, jti and a vc wrapper."""
        context = _make_context_with_status_handler(None)
        captured: dict = {}

        async def _mock_sign(profile, headers, payload, **kwargs):
            captured.update(payload)
            return _FAKE_JWS

        with patch("jwt_vc_json.cred_processor.jwt_sign", side_effect=_mock_sign):
            await JwtVcJsonCredProcessor().issue(body, supported, ex_record, pop, context)

        for claim in ("iss", "sub", "nbf", "jti", "vc"):
            assert claim in captured, f"Required JWT claim '{claim}' missing"

        vc = captured["vc"]
        assert vc["issuer"] == ex_record.issuer_id
        assert "credentialSubject" in vc
        assert vc["credentialSubject"]["id"].startswith("did:")
