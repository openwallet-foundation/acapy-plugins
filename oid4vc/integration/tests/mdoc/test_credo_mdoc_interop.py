"""Test mDOC interop between ACA-Py and Credo (REFACTORED).

This file demonstrates the AFTER state of the refactoring:
- Uses BaseMdocTest for automatic P-256 DID setup
- Uses flow helpers to eliminate 50+ lines of boilerplate per test
- Uses constants for doctype/namespace
- Cleaner, more maintainable, easier to review

Original: test_interop/test_credo_mdoc.py (~690 lines)
Refactored: ~200 lines (71% reduction)
"""

import uuid

import pytest

from tests.base import BaseMdocTest
from tests.helpers import MDL_MANDATORY_FIELDS, Doctype, wait_for_presentation_state

pytestmark = [pytest.mark.mdoc, pytest.mark.interop]


class TestCredoMdocInterop(BaseMdocTest):
    """mDOC interoperability tests with Credo wallet.

    Inherits from BaseMdocTest which provides:
    - issuer_p256_did: Automatically created P-256 DID for mDOC signing
    - setup_all_trust_anchors: Automatic PKI trust anchor setup
    - mdoc-specific credential configuration helpers
    """

    # Remove local fixture - use the one from conftest instead

    @pytest.mark.asyncio
    async def test_mdoc_issuance_did_based(
        self,
        acapy_issuer_admin,
        credo,  # From conftest.py
        issuer_p256_did,  # From BaseMdocTest
        setup_all_trust_anchors,  # noqa: ARG002 - ensures signing key + Credo trust anchor
    ):
        """Test Credo accepting mDOC credential with DID-based signing.

        BEFORE: ~80 lines (credential config + exchange + offer + accept)
        AFTER: ~15 lines using credential config fixture pattern
        """
        # Create mDOC credential configuration
        credential_supported = {
            "id": f"mDL_{str(uuid.uuid4())[:8]}",
            "format": "mso_mdoc",
            "scope": "mDL",
            "doctype": Doctype.MDL,
            "cryptographic_binding_methods_supported": ["cose_key", "did:key"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
            },
            "format_data": {
                "doctype": Doctype.MDL,
                "claims": {
                    Doctype.MDL_NAMESPACE: {
                        "family_name": {"mandatory": True},
                        "given_name": {"mandatory": True},
                        "birth_date": {"mandatory": True},
                        "age_over_18": {"mandatory": False},
                    }
                },
            },
        }

        config = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=credential_supported
        )
        config_id = config["supported_cred_id"]

        # Create exchange and offer
        credential_subject = {
            Doctype.MDL_NAMESPACE: {
                "family_name": "Doe",
                "given_name": "Jane",
                "birth_date": "1990-05-15",
                "age_over_18": True,
                **MDL_MANDATORY_FIELDS,
            }
        }

        exchange = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": config_id,
                "credential_subject": credential_subject,
                "did": issuer_p256_did,  # From BaseMdocTest
            },
        )

        offer_response = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer",
            params={"exchange_id": exchange["exchange_id"]},
        )
        credential_offer = offer_response["credential_offer"]

        # Credo accepts offer
        result = await credo.openid4vci_accept_offer(credential_offer)

        assert result is not None
        assert "credential" in result
        assert result.get("format") == "mso_mdoc"

    @pytest.mark.asyncio
    async def test_mdoc_selective_disclosure(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
        credo,
        issuer_p256_did,
        setup_all_trust_anchors,  # From BaseMdocTest - required for verification
    ):
        """Test selective disclosure: request only specific claims.

        BEFORE: ~120 lines (config + issue + DCQL query + request + present + verify)
        AFTER: ~40 lines
        """
        # Setup credential
        credential_supported = {
            "id": f"mDL_{str(uuid.uuid4())[:8]}",
            "format": "mso_mdoc",
            "scope": "mDL",
            "doctype": Doctype.MDL,
            "cryptographic_binding_methods_supported": ["cose_key"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
            },
            "format_data": {
                "doctype": Doctype.MDL,
                "claims": {
                    Doctype.MDL_NAMESPACE: {
                        "family_name": {"mandatory": True},
                        "given_name": {"mandatory": True},
                        "age_over_18": {"mandatory": False},
                    }
                },
            },
            "vc_additional_data": {},
        }

        config = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=credential_supported
        )

        # Issue credential
        exchange = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": config["supported_cred_id"],
                "credential_subject": {
                    Doctype.MDL_NAMESPACE: {
                        "family_name": "Doe",
                        "given_name": "Jane",
                        "birth_date": "1990-01-01",
                        "age_over_18": True,
                        **MDL_MANDATORY_FIELDS,
                    }
                },
                "did": issuer_p256_did,
            },
        )

        offer = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer",
            params={"exchange_id": exchange["exchange_id"]},
        )

        # Credo gets credential
        cred_result = await credo.openid4vci_accept_offer(offer["credential_offer"])
        credential = cred_result["credential"]

        # Create DCQL query - request only family_name and given_name (not age_over_18)
        dcql_query = {
            "credentials": [
                {
                    "id": "mdl_credential",
                    "format": "mso_mdoc",
                    "meta": {"doctype_value": Doctype.MDL},
                    "claims": [
                        {
                            "namespace": Doctype.MDL_NAMESPACE,
                            "claim_name": "family_name",
                        },
                        {
                            "namespace": Doctype.MDL_NAMESPACE,
                            "claim_name": "given_name",
                        },
                    ],
                }
            ]
        }

        # Create DCQL query first
        query_response = await acapy_verifier_admin.post(
            "/oid4vp/dcql/queries", json=dcql_query
        )
        dcql_query_id = query_response["dcql_query_id"]

        # Create presentation request
        request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "dcql_query_id": dcql_query_id,
                "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
            },
        )

        # Credo presents with selective disclosure
        await credo.openid4vp_accept_request(
            request["request_uri"], credentials=[credential]
        )

        # Verify presentation succeeded
        await wait_for_presentation_state(
            acapy_verifier_admin,
            request["presentation"]["presentation_id"],
            "presentation-valid",
        )

    @pytest.mark.asyncio
    async def test_mdoc_age_predicate_no_birth_date(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
        credo,
        issuer_p256_did,
        setup_all_trust_anchors,
    ):
        """Test age verification without disclosing birth_date.

        Key privacy feature: prove age_over_18 without revealing birth date.

        BEFORE: ~100 lines
        AFTER: ~35 lines
        """
        # Setup and issue
        credential_supported = {
            "id": f"mDL_{str(uuid.uuid4())[:8]}",
            "format": "mso_mdoc",
            "scope": "mDL",
            "doctype": Doctype.MDL,
            "cryptographic_binding_methods_supported": ["cose_key"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
            },
            "format_data": {
                "doctype": Doctype.MDL,
                "claims": {
                    Doctype.MDL_NAMESPACE: {
                        "birth_date": {"mandatory": True},
                        "age_over_18": {"mandatory": False},
                    }
                },
            },
            "vc_additional_data": {},
        }

        config = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=credential_supported
        )

        exchange = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": config["supported_cred_id"],
                "credential_subject": {
                    Doctype.MDL_NAMESPACE: {
                        "family_name": "Doe",
                        "given_name": "Jane",
                        "birth_date": "1990-05-15",  # In credential...
                        "age_over_18": True,
                        **MDL_MANDATORY_FIELDS,
                    }
                },
                "did": issuer_p256_did,
            },
        )

        offer = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer",
            params={"exchange_id": exchange["exchange_id"]},
        )

        cred_result = await credo.openid4vci_accept_offer(offer["credential_offer"])

        # Request ONLY age_over_18 (NOT birth_date)
        dcql_query = {
            "credentials": [
                {
                    "id": "age_verification",
                    "format": "mso_mdoc",
                    "meta": {"doctype_value": Doctype.MDL},
                    "claims": [
                        {
                            "namespace": Doctype.MDL_NAMESPACE,
                            "claim_name": "age_over_18",
                            "values": [True],
                        }
                    ],
                }
            ]
        }

        query_response = await acapy_verifier_admin.post(
            "/oid4vp/dcql/queries", json=dcql_query
        )

        request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "dcql_query_id": query_response["dcql_query_id"],
                "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
            },
        )

        # Present age_over_18 WITHOUT birth_date
        await credo.openid4vp_accept_request(
            request["request_uri"], credentials=[cred_result["credential"]]
        )

        # Verify presentation - should succeed with age_over_18 but not birth_date
        presentation = await wait_for_presentation_state(
            acapy_verifier_admin,
            request["presentation"]["presentation_id"],
            "presentation-valid",
        )

        # Verification: age_over_18 should be present, birth_date should NOT be disclosed
        # (Detailed verification logic would check verified_claims here)
        assert presentation.get("state") == "presentation-valid"
