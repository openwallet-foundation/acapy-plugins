"""Fixtures for mDOC interop tests.

This conftest provides the basic fixtures needed for test_credo_mdoc.py.
Most mDOC-specific fixtures are defined in test_credo_mdoc.py itself.
"""

import uuid
from os import getenv

import httpx
import pytest_asyncio

from acapy_controller import Controller
from credo_wrapper import CredoWrapper

# Service endpoints from docker-compose.yml environment variables
CREDO_AGENT_URL = getenv("CREDO_AGENT_URL", "http://localhost:3020")
ACAPY_ISSUER_ADMIN_URL = getenv("ACAPY_ISSUER_ADMIN_URL", "http://localhost:8021")
ACAPY_VERIFIER_ADMIN_URL = getenv("ACAPY_VERIFIER_ADMIN_URL", "http://localhost:8031")


@pytest_asyncio.fixture
async def credo():
    """Create a Credo wrapper instance."""
    wrapper = CredoWrapper(CREDO_AGENT_URL)
    async with wrapper as wrapper:
        yield wrapper


@pytest_asyncio.fixture
async def acapy_issuer():
    """HTTP client for ACA-Py issuer admin API."""
    async with httpx.AsyncClient(base_url=ACAPY_ISSUER_ADMIN_URL) as client:
        yield client


@pytest_asyncio.fixture
async def acapy_verifier():
    """HTTP client for ACA-Py verifier admin API."""
    async with httpx.AsyncClient(base_url=ACAPY_VERIFIER_ADMIN_URL) as client:
        yield client


# Legacy fixtures for backward compatibility with interop tests
# These are kept here for tests in this directory that may still use them


@pytest_asyncio.fixture
async def sphereon():
    """Sphereon wrapper - kept for legacy interop tests."""
    # Import moved here to avoid circular dependencies
    from sphereon_wrapper import SphereaonWrapper

    sphereon_wrapper_url = getenv("SPHEREON_WRAPPER_URL", "http://localhost:3030")
    wrapper = SphereaonWrapper(sphereon_wrapper_url)
    async with wrapper:
        yield wrapper


@pytest_asyncio.fixture
async def offer(acapy_issuer, issuer_p256_did):
    """Create a JWT VC credential offer for legacy tests."""
    issuer_admin = Controller(ACAPY_ISSUER_ADMIN_URL)

    # Create supported credential
    supported = await issuer_admin.post(
        "/oid4vci/credential-supported/create/jwt",
        json={
            "cryptographic_binding_methods_supported": ["did"],
            "credential_signing_alg_values_supported": ["ES256"],
            "format": "jwt_vc_json",
            "id": f"UniversityDegree_{uuid.uuid4().hex[:8]}",
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        },
    )

    # Create exchange
    exchange = await issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported["supported_cred_id"],
            "credential_subject": {"name": "alice"},
            "verification_method": issuer_p256_did + "#0",
        },
    )

    # Get offer
    offer_response = await issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    yield offer_response


@pytest_asyncio.fixture
async def issuer_p256_did(acapy_issuer):
    """P-256 issuer DID for legacy tests."""
    issuer_admin = Controller(ACAPY_ISSUER_ADMIN_URL)
    did_response = await issuer_admin.post(
        "/wallet/did/create",
        json={"method": "key", "options": {"key_type": "p256"}},
    )
    return did_response["result"]["did"]
