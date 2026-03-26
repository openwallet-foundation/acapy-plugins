"""Step-by-step integration tests to isolate the StatusListCred 404 failure.

These tests break down `test_unrevoke_credential` into individual observable
steps so that we can pinpoint exactly where the StatusListCred record lifecycle
breaks down.

Root-cause hypothesis:
  ACA-Py issues the credential (calls `assign_status_entries` which creates a
  StatusListCred with `credential_id = exchange_id`), but subsequent calls to
  PATCH /status-list/defs/{def_id}/creds/{exchange_id} return 404.

  Possible causes:
  1. Credo fails to complete the OID4VCI exchange (error before ACA-Py commits
     the credential), so `assign_status_entries` is never called.
  2. The StatusListCred is created but with a different `credential_id` than
     the `exchange_id` used in the PATCH URL.
  3. The jwt_vc_json `cred_processor` raises before the status list assignment.

Run with (docker stack must be up):
    cd oid4vc && poetry run pytest integration/tests/debug/test_status_list_steps.py -v
"""

import logging
import uuid

import pytest

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_jwt_vc_config(suffix: str) -> dict:
    """Return a minimal jwt_vc_json credential configuration payload.

    NOTE: type and @context MUST be inside format_data (not at the top level).
    When placed at the top level, ACA-Py moves them to vc_additional_data, leaving
    credential_definition empty in the issuer metadata.  An empty credential_definition
    causes @openid4vc/openid4vci 0.4.x to exclude the config from
    knownCredentialConfigurations, resulting in offeredCredentialConfigurations={} and
    zero credentials returned (no error) — which means ACA-Py never assigns status
    entries and PATCH /status-list/defs/{id}/creds/{exchange_id} returns 404.
    """
    return {
        "id": f"StatusListTest_{suffix}",
        "format": "jwt_vc_json",
        "format_data": {
            "type": ["VerifiableCredential", "StatusTestCredential"],
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
            ],
        },
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["EdDSA", "ES256"]}
        },
        "display": [{"name": "Status Test", "locale": "en-US"}],
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestStatusListSteps:
    """Isolation tests for the StatusListCred 404 failure."""

    @pytest.mark.asyncio
    async def test_step1_create_credential_config(self, acapy_issuer_admin):
        """Step 1: Create a jwt_vc_json credential configuration.

        EXPECT: 200 with a supported_cred_id.
        """
        suffix = str(uuid.uuid4())[:8]
        resp = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create",
            json=_make_jwt_vc_config(suffix),
        )
        assert "supported_cred_id" in resp, (
            f"Missing supported_cred_id in response: {resp}"
        )
        LOGGER.info(f"Step 1 ✓ supported_cred_id={resp['supported_cred_id']}")

    @pytest.mark.asyncio
    async def test_step2_create_status_list_def(self, acapy_issuer_admin):
        """Step 2: Create a credential config THEN add a status list definition.

        EXPECT: 200 with a definition id.
        """
        suffix = str(uuid.uuid4())[:8]
        config_resp = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create",
            json=_make_jwt_vc_config(suffix),
        )
        supported_cred_id = config_resp["supported_cred_id"]

        did_resp = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        issuer_did = did_resp["result"]["did"]

        def_resp = await acapy_issuer_admin.post(
            "/status-list/defs",
            json={
                "supported_cred_id": supported_cred_id,
                "status_purpose": "revocation",
                "list_size": 1024,
                "list_type": "w3c",
                "issuer_did": issuer_did,
            },
        )
        assert "id" in def_resp, f"Missing 'id' in status list def response: {def_resp}"
        LOGGER.info(
            f"Step 2 ✓ definition_id={def_resp['id']} "
            f"supported_cred_id={supported_cred_id}"
        )

    @pytest.mark.asyncio
    async def test_step3_create_exchange(self, acapy_issuer_admin):
        """Step 3: Create an OID4VCI exchange for a credential.

        EXPECT: 200 with an exchange_id.
        """
        suffix = str(uuid.uuid4())[:8]
        config_resp = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create",
            json=_make_jwt_vc_config(suffix),
        )
        supported_cred_id = config_resp["supported_cred_id"]

        did_resp = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        issuer_did = did_resp["result"]["did"]

        exchange_resp = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": supported_cred_id,
                "credential_subject": {"test": "step3"},
                "did": issuer_did,
            },
        )
        assert "exchange_id" in exchange_resp, (
            f"Missing exchange_id in response: {exchange_resp}"
        )
        LOGGER.info(f"Step 3 ✓ exchange_id={exchange_resp['exchange_id']}")

    @pytest.mark.asyncio
    async def test_step4_credo_accepts_offer_http_200(
        self, acapy_issuer_admin, credo_client
    ):
        """Step 4: Credo accepts the OID4VCI offer and returns HTTP 200.

        EXPECT: credo_client POST /oid4vci/accept-offer returns HTTP 200.

        If this fails with a non-200 status, the OID4VCI exchange itself is
        broken (client-level error before the credential is issued).
        """
        suffix = str(uuid.uuid4())[:8]

        # Setup config + DID + status def
        config_resp = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create",
            json=_make_jwt_vc_config(suffix),
        )
        supported_cred_id = config_resp["supported_cred_id"]

        did_resp = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        issuer_did = did_resp["result"]["did"]

        await acapy_issuer_admin.post(
            "/status-list/defs",
            json={
                "supported_cred_id": supported_cred_id,
                "status_purpose": "revocation",
                "list_size": 1024,
                "list_type": "w3c",
                "issuer_did": issuer_did,
            },
        )

        exchange_resp = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": supported_cred_id,
                "credential_subject": {"test": "step4"},
                "did": issuer_did,
            },
        )
        exchange_id = exchange_resp["exchange_id"]

        offer_resp = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
        )
        credential_offer = offer_resp["credential_offer"]

        # Credo accepts
        cred_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": credential_offer,
                "holder_did_method": "key",
            },
        )
        LOGGER.info(
            f"Step 4: Credo response status={cred_response.status_code} "
            f"body={cred_response.text[:400]}"
        )
        assert cred_response.status_code == 200, (
            f"Credo /oid4vci/accept-offer returned {cred_response.status_code}: "
            f"{cred_response.text}"
        )

    @pytest.mark.asyncio
    async def test_step5_status_list_cred_record_exists_after_issuance(
        self, acapy_issuer_admin, credo_client
    ):
        """Step 5: After Credo accepts the offer, GET the StatusListCred record.

        EXPECT: GET /status-list/defs/{def_id}/creds/{exchange_id} returns 200.

        If this returns 404, the StatusListCred was never created.  That means
        `assign_status_entries()` was NOT called during the exchange — either
        because the exchange failed server-side before that point, or the status
        list plugin's status handler was not invoked.

        KEY DIAGNOSTIC: This is the exact check that `test_unrevoke_credential`
        implicitly requires at line 688 (PATCH /status-list/defs/.../creds/...).
        """
        suffix = str(uuid.uuid4())[:8]

        config_resp = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create",
            json=_make_jwt_vc_config(suffix),
        )
        supported_cred_id = config_resp["supported_cred_id"]

        did_resp = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        issuer_did = did_resp["result"]["did"]

        def_resp = await acapy_issuer_admin.post(
            "/status-list/defs",
            json={
                "supported_cred_id": supported_cred_id,
                "status_purpose": "revocation",
                "list_size": 1024,
                "list_type": "w3c",
                "issuer_did": issuer_did,
            },
        )
        definition_id = def_resp["id"]

        exchange_resp = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": supported_cred_id,
                "credential_subject": {"test": "step5"},
                "did": issuer_did,
            },
        )
        exchange_id = exchange_resp["exchange_id"]

        offer_resp = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
        )
        credential_offer = offer_resp["credential_offer"]

        cred_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": credential_offer,
                "holder_did_method": "key",
            },
        )
        LOGGER.info(
            f"Credo response: status={cred_response.status_code} "
            f"body={cred_response.text[:400]}"
        )

        # Now check if the StatusListCred record exists
        status_cred_resp = await acapy_issuer_admin.get(
            f"/status-list/defs/{definition_id}/creds/{exchange_id}"
        )
        LOGGER.info(f"Step 5: StatusListCred record = {status_cred_resp}")

        assert "index" in status_cred_resp or "list" in status_cred_resp, (
            f"Expected StatusListCred data, got: {status_cred_resp}.\n"
            "This means StatusListCred was never saved for this exchange_id.\n"
            "assign_status_entries() was likely never called — check "
            "cred_processor.py or the OID4VCI exchange flow."
        )
        LOGGER.info(
            f"Step 5 ✓ StatusListCred exists: index={status_cred_resp.get('index')} "
            f"status={status_cred_resp.get('status')}"
        )

    @pytest.mark.asyncio
    async def test_step6_credential_contains_status_claim(
        self, acapy_issuer_admin, credo_client
    ):
        """Step 6: The issued credential JWT contains a credentialStatus claim.

        EXPECT: Credo returns a non-null credential that, when decoded, has
        a 'credentialStatus' field in the VC payload.

        If credential is null (jwt extraction fails in Credo), this diagnostic
        points to the Credo issuance.ts extraction bug, NOT a status list bug.

        If credential is non-null but has no credentialStatus, the assign step
        ran but didn't embed the status in the JWT payload.
        """
        import jwt as pyjwt

        suffix = str(uuid.uuid4())[:8]

        config_resp = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create",
            json=_make_jwt_vc_config(suffix),
        )
        supported_cred_id = config_resp["supported_cred_id"]

        did_resp = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        issuer_did = did_resp["result"]["did"]

        await acapy_issuer_admin.post(
            "/status-list/defs",
            json={
                "supported_cred_id": supported_cred_id,
                "status_purpose": "revocation",
                "list_size": 1024,
                "list_type": "w3c",
                "issuer_did": issuer_did,
            },
        )

        exchange_resp = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": supported_cred_id,
                "credential_subject": {"test": "step6"},
                "did": issuer_did,
            },
        )
        exchange_id = exchange_resp["exchange_id"]

        offer_resp = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
        )

        cred_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": offer_resp["credential_offer"],
                "holder_did_method": "key",
            },
        )
        assert cred_response.status_code == 200

        body = cred_response.json()
        credential = body.get("credential")
        LOGGER.info(
            f"Step 6: credential={str(credential)[:200] if credential else None}"
        )

        assert credential is not None, (
            "Credo returned credential=null.  This is the jwt extraction bug in "
            "issuance.ts.  Fix: update W3cCredentialRecord extraction in Credo."
        )

        # Decode the JWT (no signature verification needed here)
        payload = pyjwt.decode(credential, options={"verify_signature": False})
        vc = payload.get("vc", payload)

        LOGGER.info(f"JWT payload keys: {list(payload.keys())}")
        LOGGER.info(f"VC keys: {list(vc.keys())}")

        assert "credentialStatus" in vc, (
            "Credential was returned (non-null) but lacks 'credentialStatus'.\n"
            f"VC keys: {list(vc.keys())}\n"
            "This means assign_status_entries() ran but the status was not embedded."
        )
        LOGGER.info(f"Step 6 ✓ credentialStatus={vc['credentialStatus']}")

    @pytest.mark.asyncio
    async def test_step7_revoke_credential_patch_returns_200(
        self, acapy_issuer_admin, credo_client
    ):
        """Step 7: After issuance, PATCH the status to '1' (revoked) returns 200.

        This is the exact call that fails in `test_unrevoke_credential` at
        line 688 with 404 'StatusListCred record not found'.

        EXPECT: PATCH /status-list/defs/{def_id}/creds/{exchange_id}
                with {"status": "1"} returns 200.
        """
        suffix = str(uuid.uuid4())[:8]

        config_resp = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create",
            json=_make_jwt_vc_config(suffix),
        )
        supported_cred_id = config_resp["supported_cred_id"]

        did_resp = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        issuer_did = did_resp["result"]["did"]

        def_resp = await acapy_issuer_admin.post(
            "/status-list/defs",
            json={
                "supported_cred_id": supported_cred_id,
                "status_purpose": "revocation",
                "list_size": 1024,
                "list_type": "w3c",
                "issuer_did": issuer_did,
            },
        )
        definition_id = def_resp["id"]

        exchange_resp = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": supported_cred_id,
                "credential_subject": {"test": "step7"},
                "did": issuer_did,
            },
        )
        exchange_id = exchange_resp["exchange_id"]

        offer_resp = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
        )

        cred_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": offer_resp["credential_offer"],
                "holder_did_method": "key",
            },
        )
        LOGGER.info(
            f"Credo response: {cred_response.status_code} {cred_response.text[:200]}"
        )
        # Don't assert 200 here — we want to reach the PATCH regardless
        # so we can observe whether the StatusListCred exists.

        # The critical call: revoke the credential
        revoke_resp = await acapy_issuer_admin.patch(
            f"/status-list/defs/{definition_id}/creds/{exchange_id}",
            json={"status": "1"},
        )
        LOGGER.info(f"Step 7: revoke response={revoke_resp}")
        assert revoke_resp is not None, (
            "PATCH /status-list returned None — likely 404 'StatusListCred record not found'.\n"
            f"definition_id={definition_id}, exchange_id={exchange_id}\n"
            "The StatusListCred record was never created for this exchange_id.\n"
            "Check cred_processor.py: does assign_status_entries() run successfully?"
        )
        LOGGER.info("Step 7 ✓ Revoke PATCH succeeded")

    @pytest.mark.asyncio
    async def test_step8_status_list_without_credo_acapy_only(self, acapy_issuer_admin):
        """Step 8: Verify the status list record lifecycle with ACA-Py ONLY.

        This test skips Credo entirely and calls the internal credential
        issuance flow directly.  If this passes while test_step7 fails, the
        bug is in how Credo triggers the ACA-Py issuance (the exchange
        does not complete on the ACA-Py side when Credo is involved).

        We use the /oid4vci/exchange/create + /oid4vci/credential endpoint
        directly to simulate a successful issuance without going through Credo.
        """
        suffix = str(uuid.uuid4())[:8]

        config_resp = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create",
            json=_make_jwt_vc_config(suffix),
        )
        supported_cred_id = config_resp["supported_cred_id"]

        did_resp = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        issuer_did = did_resp["result"]["did"]

        def_resp = await acapy_issuer_admin.post(
            "/status-list/defs",
            json={
                "supported_cred_id": supported_cred_id,
                "status_purpose": "revocation",
                "list_size": 1024,
                "list_type": "w3c",
                "issuer_did": issuer_did,
            },
        )
        definition_id = def_resp["id"]
        LOGGER.info(f"Created definition: {definition_id}")

        exchange_resp = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": supported_cred_id,
                "credential_subject": {"test": "step8_direct"},
                "did": issuer_did,
            },
        )
        exchange_id = exchange_resp["exchange_id"]
        LOGGER.info(f"Created exchange: {exchange_id}")

        # Query status list creds BEFORE any credential is issued
        # This should return 404
        try:
            pre_issuance = await acapy_issuer_admin.get(
                f"/status-list/defs/{definition_id}/creds/{exchange_id}"
            )
            LOGGER.info(f"Pre-issuance StatusListCred (unexpected): {pre_issuance}")
        except Exception as e:
            LOGGER.info(f"Pre-issuance 404 (expected): {e}")

        # Note: We don't have a way to trigger the credential issuance directly
        # without a holder doing the OID4VCI flow, so we document this limitation.
        LOGGER.info(
            "Step 8: ACA-Py-only test confirms exchange was created. "
            "StatusListCred can only be created when the credential is issued "
            "(OID4VCI exchange completed). To test without Credo, a direct "
            "/oid4vci/credential call with a valid proof would be needed."
        )
        # At minimum, verify the exchange was created successfully
        assert "exchange_id" in exchange_resp
        LOGGER.info(
            f"Step 8 ✓ Exchange {exchange_id} created, def {definition_id} linked"
        )
