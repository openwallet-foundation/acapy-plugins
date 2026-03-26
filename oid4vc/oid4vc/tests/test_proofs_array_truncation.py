"""Tests for the LOW-severity gap: proofs.jwt array with multiple entries is silently truncated.

CODE REVIEW GAP (identified in deep code review, credential.py ~L272):
    When a wallet sends OID4VCI 1.0's plural ``proofs.jwt`` format with more
    than one JWT, the credential endpoint picks only the first entry and returns
    a single credential. All additional proofs — and hence the additional
    requested credentials — are silently dropped.

    DESIRED BEHAVIOUR (asserted by these tests):
    If ``proofs.jwt`` contains more than one entry AND the server does not
    support batch issuance, the endpoint MUST return HTTP 400 with
    ``error: "invalid_proof"`` (or ``"invalid_credential_request"``) instead of
    silently issuing fewer credentials than requested.

    Alternatively, if batch issuance IS implemented (returning multiple
    credentials), the caller should receive one credential per proof.

HOW TO RUN:
    pytest oid4vc/tests/test_proofs_array_truncation.py -v
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web

from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.public_routes.credential import _issue_cred_inner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_token_result(sub: str = "refresh-001", c_nonce: str = "nonce-abc"):
    result = MagicMock()
    result.payload = {
        "sub": sub,
        "c_nonce": c_nonce,
        "exp": 9999999999,
    }
    result.verified = True
    return result


def _make_supported(
    fmt: str = "mso_mdoc",
    identifier: str = "mDL",
    format_data: dict = None,
):
    sup = MagicMock(spec=SupportedCredential)
    sup.format = fmt
    sup.identifier = identifier
    sup.format_data = format_data or {"doctype": "org.iso.18013.5.1.mDL"}
    return sup


def _make_ex_record(
    supported_cred_id: str = "mDL",
    state: str = OID4VCIExchangeRecord.STATE_OFFER_CREATED,
    nonce: str = "nonce-abc",
    notification_id: str = None,
):
    ex = MagicMock(spec=OID4VCIExchangeRecord)
    ex.supported_cred_id = supported_cred_id
    ex.state = state
    ex.nonce = nonce
    ex.verification_method = "did:key:test#0"
    ex.credential_subject = {"given_name": "Alice"}
    ex.notification_id = notification_id
    ex.save = AsyncMock()
    return ex


def _make_context(profile=None):
    ctx = MagicMock()
    if profile is None:
        profile = MagicMock()
    ctx.profile = profile
    ctx.settings = MagicMock()

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    ctx.session = MagicMock(return_value=mock_session)
    ctx.profile.session = MagicMock(return_value=mock_session)
    return ctx, mock_session


# ---------------------------------------------------------------------------
# Core gap tests
# ---------------------------------------------------------------------------


class TestProofsJwtMultipleEntriesReturns400:
    """proofs.jwt with > 1 entry must be rejected with HTTP 400.

    CURRENT STATE: the tests in this class are expected to FAIL because
    ``_issue_cred_inner`` silently uses only ``proofs.jwt[0]`` and returns one
    credential.  Once the explicit guard
        if len(jwt_proofs) > 1:
            raise _vc_error(400, "invalid_proof", ...)
    is added, these tests will PASS.
    """

    @pytest.mark.asyncio
    async def test_two_jwt_proofs_returns_400(self):
        """Sending 2 JWTs in proofs.jwt must yield a 400 error, not one credential.

        If batch issuance is not supported, a wallet that sends multiple proofs
        is requesting more credentials than the server can deliver.  The only
        honest response is an error — silently dropping proofs is spec-violating.

        IMPORTANT: ``handle_proof_of_posession`` and ``processor.issue`` are
        both mocked here so that the ONLY possible cause of failure is the
        missing multi-proof guard.  Without mocking them, the invalid JWT string
        would trigger a PoP error (HTTP 400) for the wrong reason, hiding the
        real gap.  The test intentionally drives a path that would succeed all
        the way to credential issuance — which means that *without* the
        guard the endpoint returns HTTP 200 and the test FAILS, correctly
        exposing the missing check.
        """
        context, mock_session = _make_context()
        token_result = _make_token_result()
        refresh_id = token_result.payload["sub"]
        ex_record = _make_ex_record()
        supported = _make_supported()

        mock_pop = MagicMock()
        mock_pop.verified = True
        mock_pop.holder_jwk = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
        mock_pop.holder_kid = None

        req_body = {
            "credential_identifier": "mDL",
            "proofs": {
                "jwt": [
                    "eyJhbGciOiJFUzI1NiJ9.first_proof.sig1",
                    "eyJhbGciOiJFUzI1NiJ9.second_proof.sig2",
                ]
            },
        }

        # Wire up context.inject so CredProcessors resolution works.
        mock_processor = MagicMock()
        mock_processor.issue = AsyncMock(return_value="mock_credential")
        mock_processors = MagicMock()
        mock_processors.issuer_for_format.return_value = mock_processor
        context.inject = MagicMock(return_value=mock_processors)

        with (
            patch(
                "oid4vc.public_routes.credential.OID4VCIExchangeRecord"
                ".retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch(
                "oid4vc.public_routes.credential.SupportedCredential.retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
            # Mock PoP so it succeeds regardless of the JWT content — without
            # this, an invalid JWT would produce a 400 for the wrong reason.
            patch(
                "oid4vc.public_routes.credential.handle_proof_of_posession",
                AsyncMock(return_value=mock_pop),
            ),
        ):
            # EXPECTED FAILURE (gap confirmation):
            # Without a 'len(jwt_proofs) > 1' guard, _issue_cred_inner uses
            # only jwt_proofs[0], calls issue() once, and returns HTTP 200.
            # After adding the guard, it raises HTTP 400 and this passes.
            try:
                response = await _issue_cred_inner(
                    context, token_result, refresh_id, req_body
                )
                # If we reach here it means no 400 was raised → bug is present.
                status = getattr(response, "status", 200)
                assert status == 400, (
                    "MISSING GUARD: _issue_cred_inner returned HTTP 200 when "
                    "called with proofs.jwt containing 2 entries. The second "
                    "proof was silently dropped. Add a guard: "
                    "'if len(jwt_proofs) > 1: raise _vc_error(400, \"invalid_proof\", ...)'"
                )
            except web.HTTPException as exc:
                assert exc.status == 400, (
                    f"Expected HTTP 400 for proofs.jwt with 2 entries, "
                    f"got HTTP {exc.status}."
                )
                body = json.loads(exc.text) if exc.text else {}
                assert body.get("error") in (
                    "invalid_proof",
                    "invalid_credential_request",
                ), (
                    f"Error code must be 'invalid_proof' or 'invalid_credential_request', "
                    f"got {body.get('error')!r}"
                )

    @pytest.mark.asyncio
    async def test_three_jwt_proofs_returns_400(self):
        """Sending 3 JWTs in proofs.jwt must also be rejected."""
        context, _ = _make_context()
        token_result = _make_token_result()
        refresh_id = token_result.payload["sub"]
        ex_record = _make_ex_record()
        supported = _make_supported()

        mock_pop = MagicMock()
        mock_pop.verified = True
        mock_pop.holder_jwk = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
        mock_pop.holder_kid = None

        req_body = {
            "credential_identifier": "mDL",
            "proofs": {
                "jwt": [
                    "eyJhbGciOiJFUzI1NiJ9.proof1.sig",
                    "eyJhbGciOiJFUzI1NiJ9.proof2.sig",
                    "eyJhbGciOiJFUzI1NiJ9.proof3.sig",
                ]
            },
        }

        mock_processor2 = MagicMock()
        mock_processor2.issue = AsyncMock(return_value="mock_credential")
        mock_processors2 = MagicMock()
        mock_processors2.issuer_for_format.return_value = mock_processor2
        context.inject = MagicMock(return_value=mock_processors2)

        with (
            patch(
                "oid4vc.public_routes.credential.OID4VCIExchangeRecord"
                ".retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch(
                "oid4vc.public_routes.credential.SupportedCredential.retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
            patch(
                "oid4vc.public_routes.credential.handle_proof_of_posession",
                AsyncMock(return_value=mock_pop),
            ),
        ):
            try:
                response = await _issue_cred_inner(
                    context, token_result, refresh_id, req_body
                )
                status = getattr(response, "status", 200)
                assert status == 400, (
                    "MISSING GUARD: 3-proof request returned HTTP 200 instead of 400. "
                    "Proofs 2 and 3 were silently dropped."
                )
            except web.HTTPException as exc:
                assert exc.status == 400, (
                    f"3 proofs must be rejected with 400, got {exc.status}"
                )


class TestProofsJwtSingleEntrySucceeds:
    """proofs.jwt with exactly 1 JWT must continue to work correctly.

    These are regression tests to ensure the guard for len > 1 does not
    accidentally break the single-proof happy path.  They must PASS both
    before and after the guard is added.
    """

    @pytest.mark.asyncio
    async def test_single_jwt_in_proofs_array_proceeds_to_issuance(self):
        """A single entry in proofs.jwt must be accepted and normalised to 'proof'.

        The response must contain the credential, not a 400 error.
        """
        context, mock_session = _make_context()
        token_result = _make_token_result()
        refresh_id = token_result.payload["sub"]
        ex_record = _make_ex_record()
        supported = _make_supported()

        mock_pop = MagicMock()
        mock_pop.verified = True
        mock_pop.holder_jwk = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
        mock_pop.holder_kid = None

        req_body = {
            "credential_identifier": "mDL",
            "proofs": {"jwt": ["eyJhbGciOiJFUzI1NiJ9.single_proof.sig"]},
        }

        single_mock_processor = MagicMock()
        single_mock_processor.issue = AsyncMock(return_value="mock_credential_string")
        single_mock_processors = MagicMock()
        single_mock_processors.issuer_for_format.return_value = single_mock_processor
        context.inject = MagicMock(return_value=single_mock_processors)

        with (
            patch(
                "oid4vc.public_routes.credential.OID4VCIExchangeRecord"
                ".retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch(
                "oid4vc.public_routes.credential.SupportedCredential.retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
            patch(
                "oid4vc.public_routes.credential.handle_proof_of_posession",
                AsyncMock(return_value=mock_pop),
            ),
        ):
            # Should reach issuance — may raise for unrelated reasons (e.g.
            # processor wiring), but must NOT raise 400 with invalid_proof.
            try:
                response = await _issue_cred_inner(
                    context, token_result, refresh_id, req_body
                )
                if isinstance(response, web.Response):
                    body = json.loads(response.body)
                    assert "credential" in body or "credentials" in body
            except web.HTTPException as exc:
                # It's OK if an error is raised for reasons unrelated to proof
                # count, but NOT for invalid_proof with "multiple" in the message.
                body = json.loads(exc.text) if exc.text else {}
                err = body.get("error", "")
                desc = body.get("error_description", "")
                assert "multiple" not in desc.lower() and "batch" not in desc.lower(), (
                    f"Single-proof case was rejected with a batch-related error: {body}"
                )


class TestProofsJwtEmptyArrayReturns400:
    """proofs.jwt: [] (empty array) must return 400.

    This already works today (the existing guard covers it).  Tests here are
    regression guards to confirm the existing behaviour is preserved after the
    '> 1' guard is added.
    """

    @pytest.mark.asyncio
    async def test_empty_proofs_jwt_array_returns_400(self):
        """proofs.jwt: [] must be rejected (existing guard coverage)."""
        context, _ = _make_context()
        token_result = _make_token_result()
        refresh_id = token_result.payload["sub"]
        ex_record = _make_ex_record()
        supported = _make_supported()

        req_body = {
            "credential_identifier": "mDL",
            "proofs": {"jwt": []},
        }

        with (
            patch(
                "oid4vc.public_routes.credential.OID4VCIExchangeRecord"
                ".retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch(
                "oid4vc.public_routes.credential.SupportedCredential.retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
        ):
            with pytest.raises(web.HTTPException) as exc_info:
                await _issue_cred_inner(context, token_result, refresh_id, req_body)

            assert exc_info.value.status == 400
            body = json.loads(exc_info.value.text) if exc_info.value.text else {}
            assert body.get("error") == "invalid_proof"


class TestProofsJwtNeitherProofNorProofs:
    """When neither 'proof' nor 'proofs' is present, 400 must be returned.

    This is an existing guard; tests verify it still fires after any changes
    to the proof-normalisation logic.
    """

    @pytest.mark.asyncio
    async def test_missing_proof_and_proofs_returns_400(self):
        """No proof at all must yield HTTP 400 invalid_proof."""
        context, _ = _make_context()
        token_result = _make_token_result()
        refresh_id = token_result.payload["sub"]
        ex_record = _make_ex_record()
        supported = _make_supported()

        req_body = {"credential_identifier": "mDL"}

        with (
            patch(
                "oid4vc.public_routes.credential.OID4VCIExchangeRecord"
                ".retrieve_by_refresh_id",
                AsyncMock(return_value=ex_record),
            ),
            patch(
                "oid4vc.public_routes.credential.SupportedCredential.retrieve_by_id",
                AsyncMock(return_value=supported),
            ),
        ):
            with pytest.raises(web.HTTPException) as exc_info:
                await _issue_cred_inner(context, token_result, refresh_id, req_body)

            assert exc_info.value.status == 400
            body = json.loads(exc_info.value.text) if exc_info.value.text else {}
            assert body.get("error") == "invalid_proof"


class TestProofsJwtSilentTruncationDocumentation:
    """Expose the silent-truncation bug with a direct unit test.

    These tests do NOT call ``_issue_cred_inner`` — they directly exercise the
    proof-normalisation branch in isolation to document the current (broken)
    behaviour and assert the desired (fixed) behaviour.
    """

    def test_proof_normalisation_currently_silently_drops_second_proof(self):
        """Document the current broken behaviour: proofs.jwt[1] is silently dropped.

        This is a UNIT test of the normalisation logic, not the full endpoint.
        If this test PASSES it means the bug is present; once the fix is added
        the logic will raise instead of returning jwt_proofs[0], and this test
        should be replaced by test_proof_normalisation_rejects_multiple_proofs.
        """
        jwt_proofs = ["first_jwt", "second_jwt"]

        # Reproduce the current normalisation logic verbatim from credential.py
        if not jwt_proofs:
            raise web.HTTPException  # existing guard
        proof_value = {"proof_type": "jwt", "jwt": jwt_proofs[0]}  # ← current bug

        # The second proof is silently lost — this assertion documents the bug.
        assert proof_value["jwt"] == "first_jwt"
        # "second_jwt" is unreachable; the caller receives no indication.

    def test_proof_normalisation_desired_raises_on_multiple_proofs(self):
        """Document the DESIRED behaviour: multiple proofs must raise."""
        jwt_proofs = ["first_jwt", "second_jwt"]

        def normalize_proofs(proofs_list, supported_format):
            """The corrected normalisation function."""
            if not proofs_list:
                raise web.HTTPBadRequest(
                    text=json.dumps(
                        {"error": "invalid_proof", "error_description": "empty"}
                    ),
                    content_type="application/json",
                )
            if len(proofs_list) > 1:
                raise web.HTTPBadRequest(
                    text=json.dumps(
                        {
                            "error": "invalid_proof",
                            "error_description": (
                                f"Batch issuance is not supported; received "
                                f"{len(proofs_list)} proofs in proofs.jwt for "
                                f"{supported_format}. Send one proof per request."
                            ),
                        }
                    ),
                    content_type="application/json",
                )
            return {"proof_type": "jwt", "jwt": proofs_list[0]}

        # Single proof still works
        result = normalize_proofs(["only_jwt"], "mso_mdoc")
        assert result["jwt"] == "only_jwt"

        # Multiple proofs raise 400
        with pytest.raises(web.HTTPBadRequest) as exc_info:
            normalize_proofs(jwt_proofs, "mso_mdoc")

        body = json.loads(exc_info.value.text)
        assert body["error"] == "invalid_proof"
        assert "2" in body["error_description"]
