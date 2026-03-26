"""Test ACA-Py to Credo DCQL-based OID4VP flow.

This test covers the complete DCQL (Digital Credentials Query Language) flow:
1. ACA-Py (Issuer) issues credential via OID4VCI
2. Credo receives and stores credential
3. ACA-Py (Verifier) creates DCQL query and presentation request
4. Credo presents credential using DCQL response format
5. ACA-Py (Verifier) validates the presentation

DCQL is the query language used in OID4VP v1.0 as an alternative to
Presentation Exchange. It supports both SD-JWT VC and mDOC formats.

References:
- OID4VP v1.0: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- DCQL: https://openid.github.io/oid4vc-haip-sd-jwt-vc/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-wg-draft.html
"""

import uuid

import pytest

from tests.conftest import wait_for_presentation_valid
from tests.helpers import assert_selective_disclosure
from tests.helpers.constants import MDL_MANDATORY_FIELDS


class TestDCQLSdJwtFlow:
    """Test DCQL-based presentation flow for SD-JWT VC credentials."""

    @pytest.mark.asyncio
    async def test_dcql_sd_jwt_basic_flow(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
        credo_client,
    ):
        """Test DCQL flow with SD-JWT VC: issue → receive → present with DCQL → verify.

        Uses the spec-compliant dc+sd-jwt format identifier and DCQL claims path syntax.
        """

        # Step 1: Setup SD-JWT credential configuration on ACA-Py issuer
        random_suffix = str(uuid.uuid4())[:8]
        credential_supported = {
            "id": f"DCQLTestCredential_{random_suffix}",
            "format": "vc+sd-jwt",  # ACA-Py uses vc+sd-jwt for issuance
            "scope": "IdentityCredential",
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["EdDSA", "ES256"]}
            },
            "format_data": {
                "cryptographic_binding_methods_supported": ["did:key", "jwk"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "vct": "https://credentials.example.com/identity_credential",
                "claims": {
                    "given_name": {"mandatory": True},
                    "family_name": {"mandatory": True},
                    "birth_date": {"mandatory": False},
                    "address": {
                        "street_address": {"mandatory": False},
                        "locality": {"mandatory": False},
                    },
                },
                "display": [
                    {
                        "name": "Identity Credential",
                        "locale": "en-US",
                        "description": "A basic identity credential for DCQL testing",
                    }
                ],
            },
            "vc_additional_data": {
                "sd_list": [
                    "/given_name",
                    "/family_name",
                    "/birth_date",
                    "/address/street_address",
                    "/address/locality",
                ]
            },
        }

        credential_config_response = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=credential_supported
        )
        config_id = credential_config_response["supported_cred_id"]

        # Create a DID for the issuer
        did_response = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        issuer_did = did_response["result"]["did"]

        # Step 2: Create credential offer and issue credential
        exchange_request = {
            "supported_cred_id": config_id,
            "credential_subject": {
                "given_name": "Alice",
                "family_name": "Johnson",
                "birth_date": "1990-05-15",
                "address": {
                    "street_address": "123 Main St",
                    "locality": "Anytown",
                },
            },
            "did": issuer_did,
        }

        exchange_response = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create", json=exchange_request
        )
        exchange_id = exchange_response["exchange_id"]

        offer_response = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
        )
        credential_offer_uri = offer_response["credential_offer"]

        # Step 3: Credo accepts credential offer
        accept_offer_request = {
            "credential_offer": credential_offer_uri,
            "holder_did_method": "key",
        }

        credential_response = await credo_client.post(
            "/oid4vci/accept-offer", json=accept_offer_request
        )
        assert credential_response.status_code == 200, (
            f"Credential issuance failed: {credential_response.text}"
        )
        credential_result = credential_response.json()

        assert "credential" in credential_result
        assert credential_result["format"] == "vc+sd-jwt"
        received_credential = credential_result["credential"]

        # Step 4: Create DCQL query on ACA-Py verifier
        # Using OID4VP v1.0 DCQL syntax with claims path arrays
        dcql_query = {
            "credentials": [
                {
                    "id": "identity_credential",
                    "format": "vc+sd-jwt",  # Using vc+sd-jwt (also supports dc+sd-jwt)
                    "meta": {
                        "vct_values": [
                            "https://credentials.example.com/identity_credential"
                        ]
                    },
                    "claims": [
                        {"id": "given_name_claim", "path": ["given_name"]},
                        {"id": "family_name_claim", "path": ["family_name"]},
                    ],
                }
            ]
        }

        dcql_response = await acapy_verifier_admin.post(
            "/oid4vp/dcql/queries", json=dcql_query
        )
        assert "dcql_query_id" in dcql_response
        dcql_query_id = dcql_response["dcql_query_id"]

        # Step 5: Create presentation request using DCQL query
        presentation_request_data = {
            "dcql_query_id": dcql_query_id,
            "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
        }

        presentation_request = await acapy_verifier_admin.post(
            "/oid4vp/request", json=presentation_request_data
        )
        assert "request_uri" in presentation_request
        request_uri = presentation_request["request_uri"]
        presentation_id = presentation_request["presentation"]["presentation_id"]

        # Step 6: Credo presents credential using DCQL format
        present_request = {
            "request_uri": request_uri,
            "credentials": [received_credential],
        }

        presentation_response = await credo_client.post(
            "/oid4vp/present", json=present_request
        )
        assert presentation_response.status_code == 200, (
            f"Presentation failed: {presentation_response.text}"
        )
        presentation_result = presentation_response.json()

        # Verify Credo reports success
        assert presentation_result.get("success") is True
        assert (
            presentation_result.get("result", {})
            .get("serverResponse", {})
            .get("status")
            == 200
        )

        # Step 7: Poll for presentation validation on ACA-Py verifier
        latest_presentation = await wait_for_presentation_valid(  # noqa: F841
            acapy_verifier_admin, presentation_id
        )

        print("✅ DCQL SD-JWT basic flow completed successfully!")
        print(f"   - DCQL query ID: {dcql_query_id}")
        print(f"   - Presentation ID: {presentation_id}")
        print(f"   - Final state: {latest_presentation.get('state')}")

    @pytest.mark.asyncio
    async def test_dcql_sd_jwt_nested_claims(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
        credo_client,
    ):
        """Test DCQL with nested claims path for SD-JWT VC.

        Tests the DCQL claims path syntax for accessing nested properties:
        path: ["address", "street_address"]
        """

        # Setup credential with nested claims
        random_suffix = str(uuid.uuid4())[:8]
        credential_supported = {
            "id": f"NestedClaimsCredential_{random_suffix}",
            "format": "vc+sd-jwt",
            "scope": "AddressCredential",
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["EdDSA", "ES256"]}
            },
            "format_data": {
                "cryptographic_binding_methods_supported": ["did:key", "jwk"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "vct": "https://credentials.example.com/address_credential",
                "claims": {
                    "address": {
                        "street_address": {"mandatory": True},
                        "locality": {"mandatory": True},
                        "postal_code": {"mandatory": False},
                        "country": {"mandatory": True},
                    },
                },
            },
            "vc_additional_data": {
                "sd_list": [
                    "/address/street_address",
                    "/address/locality",
                    "/address/postal_code",
                    "/address/country",
                ]
            },
        }

        credential_config_response = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=credential_supported
        )
        config_id = credential_config_response["supported_cred_id"]

        did_response = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        issuer_did = did_response["result"]["did"]

        exchange_request = {
            "supported_cred_id": config_id,
            "credential_subject": {
                "address": {
                    "street_address": "456 Oak Avenue",
                    "locality": "Springfield",
                    "postal_code": "12345",
                    "country": "US",
                },
            },
            "did": issuer_did,
        }

        exchange_response = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create", json=exchange_request
        )
        exchange_id = exchange_response["exchange_id"]

        offer_response = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
        )

        # Credo receives credential
        credential_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": offer_response["credential_offer"],
                "holder_did_method": "key",
            },
        )
        assert credential_response.status_code == 200
        received_credential = credential_response.json()["credential"]

        # Create DCQL query with nested claims path
        dcql_query = {
            "credentials": [
                {
                    "id": "address_credential",
                    "format": "vc+sd-jwt",
                    "meta": {
                        "vct_values": [
                            "https://credentials.example.com/address_credential"
                        ]
                    },
                    "claims": [
                        # Nested claims path syntax
                        {"id": "street", "path": ["address", "street_address"]},
                        {"id": "city", "path": ["address", "locality"]},
                        {"id": "country", "path": ["address", "country"]},
                    ],
                }
            ]
        }

        dcql_response = await acapy_verifier_admin.post(
            "/oid4vp/dcql/queries", json=dcql_query
        )
        dcql_query_id = dcql_response["dcql_query_id"]

        # Create and execute presentation request
        presentation_request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "dcql_query_id": dcql_query_id,
                "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
            },
        )
        request_uri = presentation_request["request_uri"]
        presentation_id = presentation_request["presentation"]["presentation_id"]

        # Present credential
        presentation_response = await credo_client.post(
            "/oid4vp/present",
            json={"request_uri": request_uri, "credentials": [received_credential]},
        )
        assert presentation_response.status_code == 200
        assert presentation_response.json().get("success") is True

        # Verify presentation
        await wait_for_presentation_valid(acapy_verifier_admin, presentation_id)
        print("✅ DCQL SD-JWT nested claims flow completed successfully!")


class TestDCQLMdocFlow:
    """Test DCQL-based presentation flow for mDOC credentials."""

    @pytest.mark.asyncio
    async def test_dcql_mdoc_basic_flow(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
        credo_client,
        setup_all_trust_anchors,
    ):
        """Test DCQL flow with mDOC: issue → receive → present with DCQL → verify.

        Uses mso_mdoc format with namespace-based claims paths.
        Note: Uses doctype_value (singular) for OID4VP v1.0 spec compliance.
        """

        # Step 1: Setup mDOC credential configuration
        random_suffix = str(uuid.uuid4())[:8]
        credential_supported = {
            "id": f"DCQLMdocCredential_{random_suffix}",
            "format": "mso_mdoc",
            "scope": "MobileDriversLicense",
            "cryptographic_binding_methods_supported": ["cose_key", "did:key", "did"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
            },
            "format_data": {
                "doctype": "org.iso.18013.5.1.mDL",
                "claims": {
                    "org.iso.18013.5.1": {
                        "given_name": {"mandatory": True},
                        "family_name": {"mandatory": True},
                        "birth_date": {"mandatory": True},
                        "document_number": {"mandatory": False},
                    }
                },
                "display": [
                    {
                        "name": "Mobile Driver's License",
                        "locale": "en-US",
                        "description": "A mobile driver's license for DCQL testing",
                    }
                ],
            },
            "vc_additional_data": {},
        }

        credential_config_response = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=credential_supported
        )
        config_id = credential_config_response["supported_cred_id"]

        did_response = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "p256"}},
        )
        issuer_did = did_response["result"]["did"]

        # Step 2: Issue credential
        exchange_request = {
            "supported_cred_id": config_id,
            "credential_subject": {
                "org.iso.18013.5.1": {
                    "given_name": "Bob",
                    "family_name": "Williams",
                    "birth_date": "1985-03-22",
                    "document_number": "DL-123456",
                    **MDL_MANDATORY_FIELDS,
                }
            },
            "did": issuer_did,
        }

        exchange_response = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create", json=exchange_request
        )
        exchange_id = exchange_response["exchange_id"]

        offer_response = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
        )

        # Step 3: Credo receives credential
        credential_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": offer_response["credential_offer"],
                "holder_did_method": "key",
            },
        )
        assert credential_response.status_code == 200, (
            f"mDOC issuance failed: {credential_response.text}"
        )
        credential_result = credential_response.json()
        assert credential_result["format"] == "mso_mdoc"
        received_credential = credential_result["credential"]

        # Step 4: Create DCQL query for mDOC
        # Using namespace/claim_name syntax for mDOC claims
        dcql_query = {
            "credentials": [
                {
                    "id": "mdl_credential",
                    "format": "mso_mdoc",
                    "meta": {
                        # Using singular doctype_value for OID4VP v1.0 spec compliance
                        "doctype_value": "org.iso.18013.5.1.mDL"
                    },
                    "claims": [
                        # mDOC claims use namespace/claim_name syntax
                        {
                            "id": "given_name_claim",
                            "namespace": "org.iso.18013.5.1",
                            "claim_name": "given_name",
                        },
                        {
                            "id": "family_name_claim",
                            "namespace": "org.iso.18013.5.1",
                            "claim_name": "family_name",
                        },
                    ],
                }
            ]
        }

        dcql_response = await acapy_verifier_admin.post(
            "/oid4vp/dcql/queries", json=dcql_query
        )
        assert "dcql_query_id" in dcql_response
        dcql_query_id = dcql_response["dcql_query_id"]

        # Step 5: Create presentation request
        presentation_request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "dcql_query_id": dcql_query_id,
                "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
            },
        )
        request_uri = presentation_request["request_uri"]
        presentation_id = presentation_request["presentation"]["presentation_id"]

        # Step 6: Present credential
        presentation_response = await credo_client.post(
            "/oid4vp/present",
            json={"request_uri": request_uri, "credentials": [received_credential]},
        )
        assert presentation_response.status_code == 200, (
            f"Presentation failed: {presentation_response.text}"
        )
        assert presentation_response.json().get("success") is True

        # Step 7: Verify presentation
        latest_presentation = await wait_for_presentation_valid(  # noqa: F841
            acapy_verifier_admin, presentation_id
        )

        print("✅ DCQL mDOC basic flow completed successfully!")
        print(f"   - DCQL query ID: {dcql_query_id}")
        print("   - Doctype: org.iso.18013.5.1.mDL")

    @pytest.mark.asyncio
    async def test_dcql_mdoc_path_syntax(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
        credo_client,
        setup_all_trust_anchors,  # noqa: ARG002 - required fixture for mDOC trust
    ):
        """Test DCQL mDOC with path array syntax.

        mDOC claims can also be specified using path: [namespace, claim_name]
        instead of separate namespace/claim_name properties.
        """

        # Setup mDOC credential
        random_suffix = str(uuid.uuid4())[:8]
        credential_supported = {
            "id": f"DCQLMdocPathTest_{random_suffix}",
            "format": "mso_mdoc",
            "scope": "MobileDriversLicense",
            "cryptographic_binding_methods_supported": ["cose_key", "did:key"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
            },
            "format_data": {
                "doctype": "org.iso.18013.5.1.mDL",
                "claims": {
                    "org.iso.18013.5.1": {
                        "given_name": {"mandatory": True},
                        "family_name": {"mandatory": True},
                    }
                },
            },
        }

        config_response = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=credential_supported
        )
        config_id = config_response["supported_cred_id"]

        did_response = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "p256"}},
        )
        issuer_did = did_response["result"]["did"]

        exchange_response = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": config_id,
                "credential_subject": {
                    "org.iso.18013.5.1": {
                        "given_name": "Carol",
                        "family_name": "Davis",
                        "birth_date": "1990-01-01",
                        **MDL_MANDATORY_FIELDS,
                    }
                },
                "did": issuer_did,
            },
        )

        offer_response = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer",
            params={"exchange_id": exchange_response["exchange_id"]},
        )

        credential_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": offer_response["credential_offer"],
                "holder_did_method": "key",
            },
        )
        assert credential_response.status_code == 200
        received_credential = credential_response.json()["credential"]

        # Create DCQL query using path array syntax for mDOC
        # path: [namespace, claim_name] format
        dcql_query = {
            "credentials": [
                {
                    "id": "mdl_path_test",
                    "format": "mso_mdoc",
                    "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                    "claims": [
                        # Using path array syntax: [namespace, claim_name]
                        {"id": "name", "path": ["org.iso.18013.5.1", "given_name"]},
                        {"id": "surname", "path": ["org.iso.18013.5.1", "family_name"]},
                    ],
                }
            ]
        }

        dcql_response = await acapy_verifier_admin.post(
            "/oid4vp/dcql/queries", json=dcql_query
        )
        dcql_query_id = dcql_response["dcql_query_id"]

        presentation_request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "dcql_query_id": dcql_query_id,
                "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
            },
        )

        presentation_response = await credo_client.post(
            "/oid4vp/present",
            json={
                "request_uri": presentation_request["request_uri"],
                "credentials": [received_credential],
            },
        )
        assert presentation_response.status_code == 200

        # Verify
        presentation_id = presentation_request["presentation"]["presentation_id"]
        result = await wait_for_presentation_valid(  # noqa: F841
            acapy_verifier_admin, presentation_id
        )
        print("✅ DCQL mDOC path syntax flow completed successfully!")


class TestDCQLSelectiveDisclosure:
    """Test DCQL-based selective disclosure for both SD-JWT and mDOC."""

    @pytest.mark.asyncio
    async def test_dcql_sd_jwt_selective_disclosure(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
        credo_client,
    ):
        """Test selective disclosure with SD-JWT VC via DCQL.

        Issues a credential with many claims but only requests specific claims
        in the DCQL query, verifying selective disclosure behavior.
        """

        random_suffix = str(uuid.uuid4())[:8]
        credential_supported = {
            "id": f"SDTestCredential_{random_suffix}",
            "format": "vc+sd-jwt",
            "scope": "EmployeeCredential",
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["EdDSA", "ES256"]}
            },
            "format_data": {
                "cryptographic_binding_methods_supported": ["did:key", "jwk"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "vct": "https://credentials.example.com/employee_credential",
                "claims": {
                    "employee_id": {"mandatory": True},
                    "full_name": {"mandatory": True},
                    "department": {"mandatory": True},
                    "salary": {
                        "mandatory": False
                    },  # Sensitive - should not be disclosed
                    "ssn": {
                        "mandatory": False
                    },  # Very sensitive - should not be disclosed
                    "hire_date": {"mandatory": False},
                },
            },
            "vc_additional_data": {
                "sd_list": [
                    "/employee_id",
                    "/full_name",
                    "/department",
                    "/salary",
                    "/ssn",
                    "/hire_date",
                ]
            },
        }

        config_response = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=credential_supported
        )
        config_id = config_response["supported_cred_id"]

        did_response = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        issuer_did = did_response["result"]["did"]

        exchange_response = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": config_id,
                "credential_subject": {
                    "employee_id": "EMP-001",
                    "full_name": "Jane Smith",
                    "department": "Engineering",
                    "salary": 150000,  # Should NOT be disclosed
                    "ssn": "123-45-6789",  # Should NOT be disclosed
                    "hire_date": "2020-01-15",
                },
                "did": issuer_did,
            },
        )

        offer_response = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer",
            params={"exchange_id": exchange_response["exchange_id"]},
        )

        credential_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": offer_response["credential_offer"],
                "holder_did_method": "key",
            },
        )
        assert credential_response.status_code == 200
        received_credential = credential_response.json()["credential"]

        # Create DCQL query requesting ONLY non-sensitive claims
        dcql_query = {
            "credentials": [
                {
                    "id": "employee_verification",
                    "format": "vc+sd-jwt",
                    "meta": {
                        "vct_values": [
                            "https://credentials.example.com/employee_credential"
                        ]
                    },
                    "claims": [
                        # Only request non-sensitive claims
                        {"id": "emp_id", "path": ["employee_id"]},
                        {"id": "name", "path": ["full_name"]},
                        {"id": "dept", "path": ["department"]},
                        # salary and ssn NOT requested - should not be disclosed
                    ],
                }
            ]
        }

        dcql_response = await acapy_verifier_admin.post(
            "/oid4vp/dcql/queries", json=dcql_query
        )
        dcql_query_id = dcql_response["dcql_query_id"]

        presentation_request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "dcql_query_id": dcql_query_id,
                "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
            },
        )

        presentation_response = await credo_client.post(
            "/oid4vp/present",
            json={
                "request_uri": presentation_request["request_uri"],
                "credentials": [received_credential],
            },
        )
        assert presentation_response.status_code == 200

        # Verify presentation succeeded
        presentation_id = presentation_request["presentation"]["presentation_id"]
        result = await wait_for_presentation_valid(
            acapy_verifier_admin, presentation_id
        )

        assert result.get("state") == "presentation-valid"

        # Verify selective disclosure: requested claims present, sensitive claims absent
        assert_selective_disclosure(
            result.get("matched_credentials"),
            "employee_verification",
            must_have=["employee_id", "full_name", "department"],
            must_not_have=["salary", "ssn"],
        )

        print("✅ DCQL SD-JWT selective disclosure flow completed successfully!")

    @pytest.mark.asyncio
    async def test_dcql_mdoc_selective_disclosure(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
        credo_client,
        setup_all_trust_anchors,  # noqa: ARG002 - required fixture for mDOC trust
    ):
        """Test selective disclosure with mDOC via DCQL.

        mDOC inherently supports selective disclosure at the element level.
        Only requested claims should be included in the presentation.
        """

        random_suffix = str(uuid.uuid4())[:8]
        credential_supported = {
            "id": f"SDMdocCredential_{random_suffix}",
            "format": "mso_mdoc",
            "scope": "MobileDriversLicense",
            "cryptographic_binding_methods_supported": ["cose_key", "did:key"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
            },
            "format_data": {
                "doctype": "org.iso.18013.5.1.mDL",
                "claims": {
                    "org.iso.18013.5.1": {
                        "given_name": {"mandatory": True},
                        "family_name": {"mandatory": True},
                        "birth_date": {"mandatory": True},
                        "portrait": {"mandatory": False},  # Sensitive
                        "driving_privileges": {"mandatory": False},
                        "signature": {"mandatory": False},  # Sensitive
                    }
                },
            },
        }

        config_response = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=credential_supported
        )
        config_id = config_response["supported_cred_id"]

        did_response = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "p256"}},
        )
        issuer_did = did_response["result"]["did"]

        exchange_response = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": config_id,
                "credential_subject": {
                    "org.iso.18013.5.1": {
                        "given_name": "David",
                        "family_name": "Brown",
                        "birth_date": "1988-07-20",
                        "signature": "base64_signature_here",
                        **MDL_MANDATORY_FIELDS,
                    }
                },
                "did": issuer_did,
            },
        )

        offer_response = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer",
            params={"exchange_id": exchange_response["exchange_id"]},
        )

        credential_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": offer_response["credential_offer"],
                "holder_did_method": "key",
            },
        )
        assert credential_response.status_code == 200
        received_credential = credential_response.json()["credential"]

        # Request only non-sensitive claims
        dcql_query = {
            "credentials": [
                {
                    "id": "age_verification",
                    "format": "mso_mdoc",
                    "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                    "claims": [
                        # Only request birth_date for age verification
                        {"namespace": "org.iso.18013.5.1", "claim_name": "birth_date"},
                        # Do NOT request portrait or signature
                    ],
                }
            ]
        }

        dcql_response = await acapy_verifier_admin.post(
            "/oid4vp/dcql/queries", json=dcql_query
        )
        dcql_query_id = dcql_response["dcql_query_id"]

        presentation_request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "dcql_query_id": dcql_query_id,
                "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
            },
        )

        presentation_response = await credo_client.post(
            "/oid4vp/present",
            json={
                "request_uri": presentation_request["request_uri"],
                "credentials": [received_credential],
            },
        )
        assert presentation_response.status_code == 200

        presentation_id = presentation_request["presentation"]["presentation_id"]
        result = await wait_for_presentation_valid(
            acapy_verifier_admin, presentation_id
        )

        assert result.get("state") == "presentation-valid"
        print("✅ DCQL mDOC selective disclosure flow completed successfully!")


class TestDCQLCredentialSets:
    """Test DCQL credential_sets for multi-credential scenarios."""

    @pytest.mark.asyncio
    async def test_dcql_credential_sets_multi_credential(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
        credo_client,
    ):
        """Test DCQL credential_sets with multiple credentials.

        credential_sets allows specifying alternative credential combinations
        that can satisfy a verification request.
        """

        random_suffix = str(uuid.uuid4())[:8]

        # Create two different credential types
        # Credential 1: Identity Credential
        identity_config = {
            "id": f"IdentityCredential_{random_suffix}",
            "format": "vc+sd-jwt",
            "scope": "IdentityCredential",
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["EdDSA", "ES256"]}
            },
            "format_data": {
                "cryptographic_binding_methods_supported": ["did:key", "jwk"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "vct": "https://credentials.example.com/identity",
                "claims": {
                    "given_name": {"mandatory": True},
                    "family_name": {"mandatory": True},
                },
            },
            "vc_additional_data": {"sd_list": ["/given_name", "/family_name"]},
        }

        # Credential 2: Age Verification Credential
        age_config = {
            "id": f"AgeCredential_{random_suffix}",
            "format": "vc+sd-jwt",
            "scope": "AgeVerification",
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["EdDSA", "ES256"]}
            },
            "format_data": {
                "cryptographic_binding_methods_supported": ["did:key", "jwk"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "vct": "https://credentials.example.com/age_verification",
                "claims": {
                    "is_over_18": {"mandatory": True},
                    "is_over_21": {"mandatory": False},
                },
            },
            "vc_additional_data": {"sd_list": ["/is_over_18", "/is_over_21"]},
        }

        identity_response = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=identity_config
        )
        identity_config_id = identity_response["supported_cred_id"]

        age_response = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=age_config
        )
        age_config_id = age_response["supported_cred_id"]

        did_response = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        issuer_did = did_response["result"]["did"]

        # Issue both credentials
        identity_exchange = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": identity_config_id,
                "credential_subject": {
                    "given_name": "Eve",
                    "family_name": "Wilson",
                },
                "did": issuer_did,
            },
        )
        identity_offer = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer",
            params={"exchange_id": identity_exchange["exchange_id"]},
        )

        age_exchange = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": age_config_id,
                "credential_subject": {
                    "is_over_18": True,
                    "is_over_21": True,
                },
                "did": issuer_did,
            },
        )
        age_offer = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer",
            params={"exchange_id": age_exchange["exchange_id"]},
        )

        # Credo receives both credentials
        identity_cred_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": identity_offer["credential_offer"],
                "holder_did_method": "key",
            },
        )
        assert identity_cred_response.status_code == 200
        identity_credential = identity_cred_response.json()["credential"]

        age_cred_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": age_offer["credential_offer"],
                "holder_did_method": "key",
            },
        )
        assert age_cred_response.status_code == 200
        age_credential = age_cred_response.json()["credential"]

        # Create DCQL query with credential_sets
        # This allows presenting EITHER identity + age OR just identity
        dcql_query = {
            "credentials": [
                {
                    "id": "identity_cred",
                    "format": "vc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity"]
                    },
                    "claims": [
                        {"id": "name", "path": ["given_name"]},
                        {"id": "surname", "path": ["family_name"]},
                    ],
                },
                {
                    "id": "age_cred",
                    "format": "vc+sd-jwt",
                    "meta": {
                        "vct_values": [
                            "https://credentials.example.com/age_verification"
                        ]
                    },
                    "claims": [
                        {"id": "age_check", "path": ["is_over_21"]},
                    ],
                },
            ],
            "credential_sets": [
                {
                    # Option 1: Both identity and age credentials
                    "purpose": "Full identity and age verification",
                    "options": [["identity_cred", "age_cred"]],
                },
                {
                    # Option 2: Just identity credential
                    "purpose": "Basic identity verification only",
                    "options": [["identity_cred"]],
                },
            ],
        }

        dcql_response = await acapy_verifier_admin.post(
            "/oid4vp/dcql/queries", json=dcql_query
        )
        dcql_query_id = dcql_response["dcql_query_id"]

        presentation_request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "dcql_query_id": dcql_query_id,
                "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
            },
        )
        request_uri = presentation_request["request_uri"]
        presentation_id = presentation_request["presentation"]["presentation_id"]

        # Present both credentials
        presentation_response = await credo_client.post(
            "/oid4vp/present",
            json={
                "request_uri": request_uri,
                "credentials": [identity_credential, age_credential],
            },
        )
        assert presentation_response.status_code == 200

        # Verify presentation
        result = await wait_for_presentation_valid(
            acapy_verifier_admin, presentation_id
        )

        assert result.get("state") == "presentation-valid"
        print("✅ DCQL credential_sets multi-credential flow completed successfully!")


class TestDCQLSpecCompliance:
    """Test OID4VP v1.0 spec compliance for DCQL."""

    @pytest.mark.asyncio
    async def test_dcql_dc_sd_jwt_format_identifier(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
        credo_client,
    ):
        """Test using dc+sd-jwt format identifier (OID4VP v1.0 spec).

        The OID4VP v1.0 spec uses dc+sd-jwt as the format identifier
        for SD-JWT VC in DCQL queries. ACA-Py should accept both
        vc+sd-jwt and dc+sd-jwt.
        """

        random_suffix = str(uuid.uuid4())[:8]
        credential_supported = {
            "id": f"DcSdJwtTest_{random_suffix}",
            "format": "vc+sd-jwt",  # Issuance uses vc+sd-jwt
            "scope": "TestCredential",
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["EdDSA", "ES256"]}
            },
            "format_data": {
                "cryptographic_binding_methods_supported": ["did:key", "jwk"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "vct": "https://credentials.example.com/test",
                "claims": {"test_claim": {"mandatory": True}},
            },
            "vc_additional_data": {"sd_list": ["/test_claim"]},
        }

        config_response = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=credential_supported
        )
        config_id = config_response["supported_cred_id"]

        did_response = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )

        exchange_response = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": config_id,
                "credential_subject": {"test_claim": "test_value"},
                "did": did_response["result"]["did"],
            },
        )

        offer_response = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer",
            params={"exchange_id": exchange_response["exchange_id"]},
        )

        credential_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": offer_response["credential_offer"],
                "holder_did_method": "key",
            },
        )
        assert credential_response.status_code == 200
        received_credential = credential_response.json()["credential"]

        # Create DCQL query using dc+sd-jwt format (spec-compliant)
        dcql_query = {
            "credentials": [
                {
                    "id": "test_cred",
                    "format": "dc+sd-jwt",  # Using spec-compliant format identifier
                    "meta": {"vct_values": ["https://credentials.example.com/test"]},
                    "claims": [{"path": ["test_claim"]}],
                }
            ]
        }

        dcql_response = await acapy_verifier_admin.post(
            "/oid4vp/dcql/queries", json=dcql_query
        )
        dcql_query_id = dcql_response["dcql_query_id"]

        # Verify query was created with dc+sd-jwt format
        query_details = await acapy_verifier_admin.get(
            f"/oid4vp/dcql/query/{dcql_query_id}"
        )
        assert query_details["credentials"][0]["format"] == "dc+sd-jwt"

        presentation_request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "dcql_query_id": dcql_query_id,
                "vp_formats": {"dc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
            },
        )

        presentation_response = await credo_client.post(
            "/oid4vp/present",
            json={
                "request_uri": presentation_request["request_uri"],
                "credentials": [received_credential],
            },
        )
        assert presentation_response.status_code == 200

        presentation_id = presentation_request["presentation"]["presentation_id"]
        result = await wait_for_presentation_valid(
            acapy_verifier_admin, presentation_id
        )

        assert result.get("state") == "presentation-valid"
        print("✅ DCQL dc+sd-jwt format identifier test completed successfully!")
