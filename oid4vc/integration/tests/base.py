"""Base test classes for OID4VC integration tests."""

import pytest
import pytest_asyncio

from .helpers import CredentialFlowHelper, PresentationFlowHelper
from .helpers.constants import ALGORITHMS, CredentialFormat, Doctype


class BaseOID4VCTest:
    """Base class for OID4VC integration tests.

    Provides common fixtures and utilities for all OID4VC tests.
    Test classes should inherit from this or its subclasses.
    """

    @pytest_asyncio.fixture(scope="class")
    async def issuer_did(self, acapy_issuer_admin):
        """Class-scoped Ed25519 issuer DID for non-mDOC tests."""
        did_response = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
        return did_response["result"]["did"]

    @pytest_asyncio.fixture
    async def credential_flow(self, acapy_issuer_admin, credo_client):
        """Credential issuance flow helper."""
        return CredentialFlowHelper(acapy_issuer_admin, credo_client)

    @pytest_asyncio.fixture
    async def presentation_flow(self, acapy_verifier_admin, credo_client):
        """Presentation verification flow helper."""
        return PresentationFlowHelper(acapy_verifier_admin, credo_client)

    @pytest_asyncio.fixture
    async def sphereon_credential_flow(self, acapy_issuer_admin, sphereon_client):
        """Credential issuance flow helper for Sphereon wallet."""
        return CredentialFlowHelper(acapy_issuer_admin, sphereon_client)

    @pytest_asyncio.fixture
    async def sphereon_presentation_flow(self, acapy_verifier_admin, sphereon_client):
        """Presentation verification flow helper for Sphereon wallet."""
        return PresentationFlowHelper(acapy_verifier_admin, sphereon_client)


class BaseSdJwtTest(BaseOID4VCTest):
    """Base class for SD-JWT credential tests.

    Provides SD-JWT-specific configuration and helpers.
    """

    @pytest_asyncio.fixture(scope="class")
    async def sd_jwt_config_template(self):
        """Class-scoped SD-JWT configuration template."""
        return {
            "format": CredentialFormat.SD_JWT.value,
            "cryptographic_binding_methods_supported": ["did:key", "jwk"],
            "credential_signing_alg_values_supported": ALGORITHMS.SD_JWT_ALGS,
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ALGORITHMS.SD_JWT_ALGS}
            },
        }


class BaseJwtVcTest(BaseOID4VCTest):
    """Base class for JWT VC credential tests.

    Provides JWT VC-specific configuration and helpers.
    """

    @pytest_asyncio.fixture(scope="class")
    async def jwt_vc_config_template(self):
        """Class-scoped JWT VC configuration template."""
        return {
            "format": CredentialFormat.JWT_VC.value,
            "cryptographic_binding_methods_supported": ["did"],
            "credential_signing_alg_values_supported": ALGORITHMS.JWT_VC_ALGS,
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ALGORITHMS.JWT_VC_ALGS}
            },
        }


class BaseMdocTest(BaseOID4VCTest):
    """Base class for mDOC/ISO 18013-5 tests.

    mDOC tests require:
    - P-256 keys (ES256 algorithm)
    - PKI trust chain setup
    - ISO namespace handling
    """

    @pytest_asyncio.fixture(scope="class")
    async def issuer_did(self, acapy_issuer_admin):
        """Class-scoped P-256 issuer DID for mDOC tests (overrides base class)."""
        did_response = await acapy_issuer_admin.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "p256"}},
        )
        return did_response["result"]["did"]

    @pytest_asyncio.fixture(scope="class")
    async def mdoc_config_template(self):
        """Class-scoped mDOC configuration template."""
        return {
            "format": CredentialFormat.MDOC.value,
            "doctype": Doctype.MDL,
            "cryptographic_binding_methods_supported": ["cose_key", "did:key", "did"],
            "credential_signing_alg_values_supported": ALGORITHMS.MDOC_ALGS,
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ALGORITHMS.MDOC_ALGS}
            },
        }

    @pytest_asyncio.fixture
    async def credential_flow(
        self, acapy_issuer_admin, credo_client, setup_issuer_certs
    ):
        """Credential issuance flow helper with mDOC signing keys pre-configured."""
        return CredentialFlowHelper(
            acapy_issuer_admin,
            credo_client,
        )


class BaseDCQLTest(BaseOID4VCTest):
    """Base class for DCQL (Digital Credentials Query Language) tests.

    DCQL tests use the controller fixture (alias for verifier admin).
    """

    @pytest_asyncio.fixture
    async def controller(self, acapy_verifier_admin):
        """Controller fixture for DCQL tests - uses verifier admin API."""
        return acapy_verifier_admin


class BaseRevocationTest(BaseOID4VCTest):
    """Base class for revocation tests.

    Revocation tests require function-scoped credential fixtures to avoid
    state pollution between tests (one test's revocation affecting another).
    """

    # Override to use function scope for credential configs in revocation tests
    @pytest.fixture(scope="function")
    def credential_config_scope(self):
        """Explicitly use function scope for credentials in revocation tests."""
        return "function"


class BaseCrossWalletTest(BaseOID4VCTest):
    """Base class for cross-wallet compatibility tests.

    Tests interoperability between different wallet implementations
    (Credo, Sphereon, etc.).
    """

    @pytest_asyncio.fixture
    async def credo_flow(self, acapy_issuer_admin, acapy_verifier_admin, credo_client):
        """Combined credential and presentation flows for Credo."""
        return {
            "credential": CredentialFlowHelper(acapy_issuer_admin, credo_client),
            "presentation": PresentationFlowHelper(acapy_verifier_admin, credo_client),
        }

    @pytest_asyncio.fixture
    async def sphereon_flow(
        self, acapy_issuer_admin, acapy_verifier_admin, sphereon_client
    ):
        """Combined credential and presentation flows for Sphereon."""
        return {
            "credential": CredentialFlowHelper(acapy_issuer_admin, sphereon_client),
            "presentation": PresentationFlowHelper(
                acapy_verifier_admin, sphereon_client
            ),
        }


class BaseValidationTest(BaseOID4VCTest):
    """Base class for validation and compliance tests.

    Tests for OID4VCI/OID4VP specification compliance, error handling,
    and edge cases.
    """

    pass
