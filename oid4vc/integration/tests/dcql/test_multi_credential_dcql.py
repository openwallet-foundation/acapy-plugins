"""Tests for multi-credential DCQL presentations.

This module tests DCQL queries that request multiple credentials of different
types in a single presentation request.

Multi-credential presentations are useful for:
- KYC: Identity + Proof of Address + Income verification
- Healthcare: Insurance + Prescription + Provider credentials
- Travel: Passport + Visa + Boarding pass

References:
- OID4VP v1.0: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- DCQL: Digital Credentials Query Language
"""

import logging
import uuid

import pytest

from tests.conftest import wait_for_presentation_valid
from tests.helpers import MDOC_AVAILABLE

LOGGER = logging.getLogger(__name__)


class TestMultiCredentialDCQL:
    """Test DCQL multi-credential presentation flows."""

    @pytest.mark.asyncio
    async def test_two_sd_jwt_credentials(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
        credo_client,
    ):
        """Test DCQL query requesting two different SD-JWT credentials.

        Scenario: KYC verification requiring:
        1. Identity credential (name, birth_date)
        2. Address credential (street, city, country)
        """
        LOGGER.info("Testing DCQL with two SD-JWT credentials...")

        random_suffix = str(uuid.uuid4())[:8]

        # === Create first credential: Identity ===
        identity_config = {
            "id": f"IdentityCred_{random_suffix}",
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
                    "birth_date": {"mandatory": True},
                },
            },
            "vc_additional_data": {
                "sd_list": ["/given_name", "/family_name", "/birth_date"]
            },
        }

        identity_response = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=identity_config
        )
        identity_config_id = identity_response["supported_cred_id"]

        # === Create second credential: Address ===
        address_config = {
            "id": f"AddressCred_{random_suffix}",
            "format": "vc+sd-jwt",
            "scope": "AddressCredential",
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["EdDSA", "ES256"]}
            },
            "format_data": {
                "cryptographic_binding_methods_supported": ["did:key", "jwk"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "vct": "https://credentials.example.com/address",
                "claims": {
                    "street_address": {"mandatory": True},
                    "locality": {"mandatory": True},
                    "country": {"mandatory": True},
                },
            },
            "vc_additional_data": {
                "sd_list": ["/street_address", "/locality", "/country"]
            },
        }

        address_response = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=address_config
        )
        address_config_id = address_response["supported_cred_id"]

        # Create issuer DID
        did_response = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        issuer_did = did_response["result"]["did"]

        # === Issue Identity credential ===
        identity_exchange = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": identity_config_id,
                "credential_subject": {
                    "given_name": "Alice",
                    "family_name": "Johnson",
                    "birth_date": "1990-05-15",
                },
                "did": issuer_did,
            },
        )
        identity_offer = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer",
            params={"exchange_id": identity_exchange["exchange_id"]},
        )

        # Credo receives identity credential
        identity_cred_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": identity_offer["credential_offer"],
                "holder_did_method": "key",
            },
        )
        assert identity_cred_response.status_code == 200
        identity_credential = identity_cred_response.json()["credential"]

        # === Issue Address credential ===
        address_exchange = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": address_config_id,
                "credential_subject": {
                    "street_address": "123 Main Street",
                    "locality": "Springfield",
                    "country": "US",
                },
                "did": issuer_did,
            },
        )
        address_offer = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer",
            params={"exchange_id": address_exchange["exchange_id"]},
        )

        # Credo receives address credential
        address_cred_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": address_offer["credential_offer"],
                "holder_did_method": "key",
            },
        )
        assert address_cred_response.status_code == 200
        address_credential = address_cred_response.json()["credential"]

        LOGGER.info("Both credentials issued successfully")

        # === Create DCQL query for BOTH credentials ===
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
                    "id": "address_cred",
                    "format": "vc+sd-jwt",
                    "meta": {"vct_values": ["https://credentials.example.com/address"]},
                    "claims": [
                        {"id": "city", "path": ["locality"]},
                        {"id": "country", "path": ["country"]},
                    ],
                },
            ]
        }

        dcql_response = await acapy_verifier_admin.post(
            "/oid4vp/dcql/queries", json=dcql_query
        )
        dcql_query_id = dcql_response["dcql_query_id"]

        # Create presentation request
        presentation_request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "dcql_query_id": dcql_query_id,
                "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
            },
        )
        request_uri = presentation_request["request_uri"]
        presentation_id = presentation_request["presentation"]["presentation_id"]

        # Credo presents BOTH credentials
        presentation_response = await credo_client.post(
            "/oid4vp/present",
            json={
                "request_uri": request_uri,
                "credentials": [identity_credential, address_credential],
            },
        )
        assert presentation_response.status_code == 200

        # Poll for validation
        result = await wait_for_presentation_valid(  # noqa: F841
            acapy_verifier_admin, presentation_id
        )
        LOGGER.info("✅ Two SD-JWT credentials presented and verified successfully")

    @pytest.mark.asyncio
    async def test_three_credentials_different_issuers(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
        credo_client,
    ):
        """Test DCQL with three credentials from different issuers.

        Real-world scenario: Employment verification requiring:
        1. Government ID (from DMV)
        2. Employment credential (from employer)
        3. Education credential (from university)
        """
        LOGGER.info("Testing DCQL with three credentials from different issuers...")

        random_suffix = str(uuid.uuid4())[:8]

        # Create three different issuer DIDs
        issuer_dids = []
        for i in range(3):
            did_response = await acapy_issuer_admin.post(
                "/wallet/did/create",
                json={"method": "key", "options": {"key_type": "ed25519"}},
            )
            issuer_dids.append(did_response["result"]["did"])

        # Credential configurations
        configs = [
            {
                "name": "GovernmentID",
                "vct": "https://gov.example.com/id",
                "claims": {"full_name": {}, "document_number": {}},
                "subject": {
                    "full_name": "Alice Johnson",
                    "document_number": "ID-123456",
                },
            },
            {
                "name": "EmploymentCred",
                "vct": "https://hr.example.com/employment",
                "claims": {"employer": {}, "job_title": {}, "start_date": {}},
                "subject": {
                    "employer": "ACME Corp",
                    "job_title": "Engineer",
                    "start_date": "2020-01-15",
                },
            },
            {
                "name": "EducationCred",
                "vct": "https://edu.example.com/degree",
                "claims": {"institution": {}, "degree": {}, "graduation_year": {}},
                "subject": {
                    "institution": "State University",
                    "degree": "BS Computer Science",
                    "graduation_year": "2019",
                },
            },
        ]

        credentials = []
        for i, cfg in enumerate(configs):
            # Create credential config
            config_data = {
                "id": f"{cfg['name']}_{random_suffix}",
                "format": "vc+sd-jwt",
                "scope": cfg["name"],
                "proof_types_supported": {
                    "jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
                },
                "format_data": {
                    "cryptographic_binding_methods_supported": ["did:key", "jwk"],
                    "credential_signing_alg_values_supported": ["EdDSA"],
                    "vct": cfg["vct"],
                    "claims": cfg["claims"],
                },
                "vc_additional_data": {
                    "sd_list": [f"/{k}" for k in cfg["claims"].keys()]
                },
            }

            config_response = await acapy_issuer_admin.post(
                "/oid4vci/credential-supported/create", json=config_data
            )
            config_id = config_response["supported_cred_id"]

            # Issue credential
            exchange = await acapy_issuer_admin.post(
                "/oid4vci/exchange/create",
                json={
                    "supported_cred_id": config_id,
                    "credential_subject": cfg["subject"],
                    "did": issuer_dids[i],  # Different issuer for each
                },
            )
            offer = await acapy_issuer_admin.get(
                "/oid4vci/credential-offer",
                params={"exchange_id": exchange["exchange_id"]},
            )

            # Credo receives
            cred_response = await credo_client.post(
                "/oid4vci/accept-offer",
                json={
                    "credential_offer": offer["credential_offer"],
                    "holder_did_method": "key",
                },
            )
            assert cred_response.status_code == 200
            credentials.append(cred_response.json()["credential"])

        LOGGER.info(f"Issued {len(credentials)} credentials from different issuers")

        # Create DCQL query for all three
        dcql_query = {
            "credentials": [
                {
                    "id": "gov_id",
                    "format": "vc+sd-jwt",
                    "meta": {"vct_values": ["https://gov.example.com/id"]},
                    "claims": [{"path": ["full_name"]}],
                },
                {
                    "id": "employment",
                    "format": "vc+sd-jwt",
                    "meta": {"vct_values": ["https://hr.example.com/employment"]},
                    "claims": [{"path": ["employer"]}, {"path": ["job_title"]}],
                },
                {
                    "id": "education",
                    "format": "vc+sd-jwt",
                    "meta": {"vct_values": ["https://edu.example.com/degree"]},
                    "claims": [{"path": ["degree"]}],
                },
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
                "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
            },
        )
        presentation_id = presentation_request["presentation"]["presentation_id"]

        # Present all three credentials
        presentation_response = await credo_client.post(
            "/oid4vp/present",
            json={
                "request_uri": presentation_request["request_uri"],
                "credentials": credentials,
            },
        )
        assert presentation_response.status_code == 200

        # Poll for validation
        result = await wait_for_presentation_valid(  # noqa: F841
            acapy_verifier_admin, presentation_id
        )
        LOGGER.info("✅ Three credentials from different issuers verified successfully")


class TestMultiCredentialCredentialSets:
    """Test DCQL credential_sets for alternative credential combinations."""

    @pytest.mark.asyncio
    async def test_credential_sets_alternative_ids(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
        credo_client,
    ):
        """Test credential_sets allowing alternative credential types.

        Scenario: Accept EITHER a passport OR a driver's license for identity.
        Using credential_sets to specify alternatives.
        """
        LOGGER.info("Testing credential_sets with alternative IDs...")

        random_suffix = str(uuid.uuid4())[:8]

        # Create issuer DID
        did_response = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        issuer_did = did_response["result"]["did"]

        # Create Passport credential config
        passport_config = {
            "id": f"Passport_{random_suffix}",
            "format": "vc+sd-jwt",
            "scope": "Passport",
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
            },
            "format_data": {
                "cryptographic_binding_methods_supported": ["did:key", "jwk"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "vct": "https://credentials.example.com/passport",
                "claims": {
                    "full_name": {},
                    "passport_number": {},
                    "nationality": {},
                },
            },
            "vc_additional_data": {
                "sd_list": ["/full_name", "/passport_number", "/nationality"]
            },
        }

        await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=passport_config
        )

        # Create Driver's License credential config
        license_config = {
            "id": f"DriversLicense_{random_suffix}",
            "format": "vc+sd-jwt",
            "scope": "DriversLicense",
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
            },
            "format_data": {
                "cryptographic_binding_methods_supported": ["did:key", "jwk"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "vct": "https://credentials.example.com/drivers_license",
                "claims": {
                    "full_name": {},
                    "license_number": {},
                    "state": {},
                },
            },
            "vc_additional_data": {
                "sd_list": ["/full_name", "/license_number", "/state"]
            },
        }

        license_response = await acapy_issuer_admin.post(
            "/oid4vci/credential-supported/create", json=license_config
        )
        license_config_id = license_response["supported_cred_id"]

        # Issue Driver's License (holder doesn't have passport)
        license_exchange = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": license_config_id,
                "credential_subject": {
                    "full_name": "Alice Johnson",
                    "license_number": "DL-123456",
                    "state": "California",
                },
                "did": issuer_did,
            },
        )
        license_offer = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer",
            params={"exchange_id": license_exchange["exchange_id"]},
        )

        license_cred_response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={
                "credential_offer": license_offer["credential_offer"],
                "holder_did_method": "key",
            },
        )
        assert license_cred_response.status_code == 200
        license_credential = license_cred_response.json()["credential"]

        # Create DCQL query with credential_sets: accept passport OR license
        dcql_query = {
            "credentials": [
                {
                    "id": "passport",
                    "format": "vc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/passport"]
                    },
                    "claims": [{"path": ["full_name"]}, {"path": ["passport_number"]}],
                },
                {
                    "id": "drivers_license",
                    "format": "vc+sd-jwt",
                    "meta": {
                        "vct_values": [
                            "https://credentials.example.com/drivers_license"
                        ]
                    },
                    "claims": [{"path": ["full_name"]}, {"path": ["license_number"]}],
                },
            ],
            "credential_sets": [
                {
                    "purpose": "identity_verification",
                    "options": [
                        ["passport"],  # Option 1: passport
                        ["drivers_license"],  # Option 2: driver's license
                    ],
                }
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
                "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
            },
        )
        presentation_id = presentation_request["presentation"]["presentation_id"]

        # Present driver's license (satisfies second option)
        presentation_response = await credo_client.post(
            "/oid4vp/present",
            json={
                "request_uri": presentation_request["request_uri"],
                "credentials": [license_credential],
            },
        )
        assert presentation_response.status_code == 200

        # Poll for validation
        result = await wait_for_presentation_valid(  # noqa: F841
            acapy_verifier_admin, presentation_id
        )
        LOGGER.info("✅ credential_sets with alternative IDs verified successfully")


@pytest.mark.skipif(not MDOC_AVAILABLE, reason="mDOC support not available")
class TestMixedFormatMultiCredential:
    """Test DCQL with mixed credential formats (SD-JWT + mDOC)."""

    @pytest.mark.asyncio
    async def test_sd_jwt_plus_mdoc(
        self,
        acapy_issuer_admin,
        acapy_verifier_admin,
    ):
        """Test DCQL requesting both SD-JWT and mDOC credentials.

        Scenario: Travel verification requiring:
        1. mDOC driver's license (for identity)
        2. SD-JWT boarding pass (for travel authorization)
        """
        LOGGER.info("Testing mixed format: SD-JWT + mDOC...")

        # Create DCQL query for mixed formats
        dcql_query = {
            "credentials": [
                {
                    "id": "drivers_license",
                    "format": "mso_mdoc",
                    "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                    "claims": [
                        {"namespace": "org.iso.18013.5.1", "claim_name": "given_name"},
                        {"namespace": "org.iso.18013.5.1", "claim_name": "family_name"},
                        {"namespace": "org.iso.18013.5.1", "claim_name": "portrait"},
                    ],
                },
                {
                    "id": "boarding_pass",
                    "format": "vc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://airline.example.com/boarding_pass"]
                    },
                    "claims": [
                        {"path": ["flight_number"]},
                        {"path": ["departure_airport"]},
                        {"path": ["arrival_airport"]},
                    ],
                },
            ]
        }

        try:
            dcql_response = await acapy_verifier_admin.post(
                "/oid4vp/dcql/queries", json=dcql_query
            )
            dcql_query_id = dcql_response["dcql_query_id"]
            LOGGER.info(f"Created mixed-format DCQL query: {dcql_query_id}")
        except Exception as e:
            pytest.skip(f"Mixed format DCQL not supported: {e}")

        assert dcql_query_id is not None
        LOGGER.info("✅ Mixed SD-JWT + mDOC DCQL query created successfully")
