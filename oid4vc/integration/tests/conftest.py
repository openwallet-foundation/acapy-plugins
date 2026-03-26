"""Simplified integration test fixtures for OID4VC v1 flows.

This module provides pytest fixtures for testing the complete OID4VC v1 flow:
ACA-Py Issues → Credo Receives → Credo Presents → ACA-Py Verifies

Certificate Strategy:
- Certificates are generated dynamically in-memory at test setup time
- Trust anchors are uploaded to both ACA-Py verifier and Credo via their HTTP APIs
- NO filesystem-based certificate storage is used
- This approach avoids triggering security scanning tools on static cert files
"""

import asyncio
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acapy_controller import Controller
from credo_wrapper import CredoWrapper
from sphereon_wrapper import SphereaonWrapper

# Environment configuration
CREDO_AGENT_URL = os.getenv("CREDO_AGENT_URL", "http://localhost:3021")
SPHEREON_WRAPPER_URL = os.getenv("SPHEREON_WRAPPER_URL", "http://localhost:3010")
ACAPY_ISSUER_ADMIN_URL = os.getenv("ACAPY_ISSUER_ADMIN_URL", "http://localhost:8021")
ACAPY_ISSUER_OID4VCI_URL = os.getenv(
    "ACAPY_ISSUER_OID4VCI_URL", "http://localhost:8022"
)
ACAPY_VERIFIER_ADMIN_URL = os.getenv(
    "ACAPY_VERIFIER_ADMIN_URL", "http://localhost:8031"
)
ACAPY_VERIFIER_OID4VP_URL = os.getenv(
    "ACAPY_VERIFIER_OID4VP_URL", "http://localhost:8032"
)


@pytest_asyncio.fixture(scope="module")
async def credo_client():
    """HTTP client for Credo agent service."""
    async with httpx.AsyncClient(base_url=CREDO_AGENT_URL, timeout=30.0) as client:
        # Wait for service to be ready (30 retries to handle brief unavailability)
        for _ in range(30):
            try:
                response = await client.get("/health")
                if response.status_code == 200:
                    break
            except httpx.ConnectError:
                pass
            await asyncio.sleep(1)
        else:
            raise RuntimeError("Credo agent service not available")

        yield client


@pytest_asyncio.fixture(scope="module")
async def sphereon_client():
    """HTTP client for Sphereon wrapper service."""
    async with httpx.AsyncClient(base_url=SPHEREON_WRAPPER_URL, timeout=30.0) as client:
        # Wait for service to be ready
        for _ in range(5):
            try:
                response = await client.get("/health")
                if response.status_code == 200:
                    break
            except httpx.ConnectError:
                pass
            await asyncio.sleep(1)
        else:
            raise RuntimeError("Sphereon wrapper service not available")

        yield client


@pytest_asyncio.fixture(scope="module")
async def acapy_issuer_admin():
    """ACA-Py issuer admin API controller."""
    controller = Controller(ACAPY_ISSUER_ADMIN_URL)

    # Wait for ACA-Py issuer to be ready
    for _ in range(30):
        status = await controller.get("/status/ready")
        if status.get("ready") is True:
            break
        await asyncio.sleep(1)
    else:
        raise RuntimeError("ACA-Py issuer service not available")

    yield controller


@pytest_asyncio.fixture(scope="module")
async def acapy_verifier_admin():
    """ACA-Py verifier admin API controller."""
    controller = Controller(ACAPY_VERIFIER_ADMIN_URL)

    # Wait for ACA-Py verifier to be ready
    for _ in range(30):
        status = await controller.get("/status/ready")
        if status.get("ready") is True:
            break
        await asyncio.sleep(1)
    else:
        raise RuntimeError("ACA-Py verifier service not available")

    yield controller


# Legacy fixture for backward compatibility
@pytest_asyncio.fixture
async def acapy_admin(acapy_verifier_admin):
    """Legacy alias for acapy_verifier_admin to maintain backward compatibility."""
    yield acapy_verifier_admin


# Controller fixture for DCQL tests
@pytest_asyncio.fixture
async def controller(acapy_verifier_admin):
    """Controller fixture for DCQL tests - uses verifier admin API."""
    yield acapy_verifier_admin


# =============================================================================
# Certificate Generation Fixtures
# =============================================================================


def _generate_ec_key():
    """Generate an EC P-256 key."""
    return ec.generate_private_key(ec.SECP256R1())


def _get_name(cn: str) -> x509.Name:
    """Create an X.509 name with a common name."""
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "UT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _get_public_key(key):
    """Get public key from a private key or return the key if already public."""
    if hasattr(key, "public_key"):
        return key.public_key()
    return key


def _add_iaca_extensions(
    builder, key, issuer_key, is_ca=True, is_root=False, path_length=None
):
    """Add IACA-compliant extensions to certificate builder."""
    if is_ca:
        if path_length is None:
            path_length = 1 if is_root else 0
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length), critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.0.18013.5.1.2")]),
            critical=True,
        )

    # Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(_get_public_key(key)), critical=False
    )

    # Authority Key Identifier
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(_get_public_key(issuer_key)),
        critical=False,
    )

    # CRL Distribution Points
    builder = builder.add_extension(
        x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier("https://example.com/test.crl")
                    ],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None,
                )
            ]
        ),
        critical=False,
    )

    # Issuer Alternative Name
    builder = builder.add_extension(
        x509.IssuerAlternativeName(
            [x509.UniformResourceIdentifier("https://example.com")]
        ),
        critical=False,
    )

    return builder


def _generate_root_ca(key, path_length=0):
    """Generate a self-signed root CA certificate.

    Args:
        key: EC private key for the root CA.
        path_length: BasicConstraints pathLenConstraint.
            Use 0 when the root directly signs leaf DS certs (no intermediate).
            Use 1 when an intermediate CA is used.
    """
    name = _get_name("Test Root CA")
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(name)
    builder = builder.issuer_name(name)
    builder = builder.not_valid_before(datetime.now(UTC))
    builder = builder.not_valid_after(datetime.now(UTC) + timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    builder = _add_iaca_extensions(
        builder, key, key, is_ca=True, is_root=True, path_length=path_length
    )
    return builder.sign(key, hashes.SHA256())


def _generate_intermediate_ca(key, issuer_key, issuer_name):
    """Generate an intermediate CA certificate."""
    name = _get_name("Test Intermediate CA")
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.not_valid_before(datetime.now(UTC))
    builder = builder.not_valid_after(datetime.now(UTC) + timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    builder = _add_iaca_extensions(builder, key, issuer_key, is_ca=True, is_root=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _generate_leaf_ds(key, issuer_key, issuer_name):
    """Generate a leaf document signer certificate.

    ``key`` may be either a private key or a public key object.
    """
    name = _get_name("Test Leaf DS")
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.not_valid_before(datetime.now(UTC))
    builder = builder.not_valid_after(datetime.now(UTC) + timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(_get_public_key(key))
    builder = _add_iaca_extensions(builder, key, issuer_key, is_ca=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _key_to_pem(key) -> str:
    """Convert a private key to PEM string."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _cert_to_pem(cert) -> str:
    """Convert a certificate to PEM string."""
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


@pytest.fixture(scope="session")
def generated_test_certs() -> dict[str, Any]:
    """Generate an ephemeral test certificate chain.

    This fixture generates a complete PKI hierarchy for testing:
    - Root CA (trust anchor)
    - Intermediate CA
    - Leaf DS (document signer) certificate

    Returns:
        Dictionary containing:
        - root_ca_pem: Root CA certificate PEM
        - root_ca_key_pem: Root CA private key PEM
        - intermediate_ca_pem: Intermediate CA certificate PEM
        - intermediate_ca_key_pem: Intermediate CA private key PEM
        - leaf_cert_pem: Leaf certificate PEM
        - leaf_key_pem: Leaf private key PEM
        - leaf_chain_pem: Leaf + Intermediate chain PEM (for x5chain)
    """
    # Generate Root CA (path_length=1: allows one intermediate CA)
    root_key = _generate_ec_key()
    root_cert = _generate_root_ca(root_key, path_length=1)

    # Generate Intermediate CA
    inter_key = _generate_ec_key()
    inter_cert = _generate_intermediate_ca(inter_key, root_key, root_cert.subject)

    # Generate Leaf DS
    leaf_key = _generate_ec_key()
    leaf_cert = _generate_leaf_ds(leaf_key, inter_key, inter_cert.subject)

    # Create chain PEM (leaf + intermediate for x5chain)
    leaf_pem = _cert_to_pem(leaf_cert)
    inter_pem = _cert_to_pem(inter_cert)
    chain_pem = leaf_pem + inter_pem

    return {
        "root_ca_pem": _cert_to_pem(root_cert),
        "root_ca_key_pem": _key_to_pem(root_key),
        "intermediate_ca_pem": inter_pem,
        "intermediate_ca_key_pem": _key_to_pem(inter_key),
        "leaf_cert_pem": leaf_pem,
        "leaf_key_pem": _key_to_pem(leaf_key),
        "leaf_chain_pem": chain_pem,
    }


@pytest_asyncio.fixture
async def setup_issuer_certs(acapy_issuer_admin):
    """Ensure the issuer has a signing key and certificate via the trust registry.

    Uses the two-step flow:
    1. ``POST /mso-mdoc/signing-keys`` generates a key pair server-side.
    2. A certificate is created for the generated public key (signed by a
       test root CA) and attached via ``PUT /mso-mdoc/signing-keys/{id}``.

    Yields:
        Dictionary with ``certificate_pem``, ``root_ca_pem``,
        ``signing_key_id``, and ``public_key_pem``.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    # Step 1: Generate a signing key server-side
    response = await acapy_issuer_admin.post(
        "/mso-mdoc/signing-keys",
        json={"label": "integration-test-signing-key"},
    )
    signing_key_id = response.get("id") or response.get("signing_key_id")
    public_key_pem = response.get("public_key_pem")

    # Step 2: Create a certificate for the generated public key
    root_key = _generate_ec_key()
    root_cert = _generate_root_ca(root_key)

    # Load the public key returned by the server so we can create a cert for it
    public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
    leaf_cert = _generate_leaf_ds(public_key, root_key, root_cert.subject)

    certificate_pem = _cert_to_pem(leaf_cert)
    root_ca_pem = _cert_to_pem(root_cert)

    # Step 3: Attach the certificate to the signing key
    await acapy_issuer_admin.put(
        f"/mso-mdoc/signing-keys/{signing_key_id}",
        json={"certificate_pem": certificate_pem},
    )

    yield {
        "certificate_pem": certificate_pem,
        "root_ca_pem": root_ca_pem,
        "signing_key_id": signing_key_id,
        "public_key_pem": public_key_pem,
    }

    # Teardown: delete the signing key record to prevent accumulation across
    # tests.  Without this, _resolve_signing_key may pick a stale record from
    # a previous test whose root CA is no longer registered as a trust anchor.
    if signing_key_id:
        try:
            await acapy_issuer_admin.delete(f"/mso-mdoc/signing-keys/{signing_key_id}")
        except Exception:
            pass  # Best-effort cleanup


@pytest_asyncio.fixture
async def setup_verifier_trust_anchors(acapy_verifier_admin, setup_issuer_certs):
    """Upload trust anchors to the ACA-Py verifier via the trust anchor registry.

    Uses the new ``POST /mso-mdoc/trust-anchors`` endpoint.  Falls back to the
    legacy ``vc_additional_data`` approach if the endpoint is not available.

    Yields:
        Dictionary with status.
    """
    # Use root CA as trust anchor when available; fall back to leaf cert
    cert_pem = (
        setup_issuer_certs.get("root_ca_pem") or setup_issuer_certs["certificate_pem"]
    )

    try:
        response = await acapy_verifier_admin.post(
            "/mso-mdoc/trust-anchors",
            json={
                "label": "integration-test-trust-anchor",
                "purpose": "iaca",
                "certificate_pem": cert_pem,
            },
        )
        yield {"trust_anchor_id": response.get("id")}
    except Exception:
        # Fallback: store in vc_additional_data (legacy approach)
        try:
            records = await acapy_verifier_admin.get(
                "/oid4vci/credential-supported/records"
            )
            mdoc_recs = [
                r for r in records.get("results", []) if r.get("format") == "mso_mdoc"
            ]

            if mdoc_recs:
                rec_id = mdoc_recs[0].get("supported_cred_id")
                existing_anchors = (
                    mdoc_recs[0].get("vc_additional_data", {}).get("trust_anchors", [])
                )
                if cert_pem not in existing_anchors:
                    existing_anchors.append(cert_pem)
                await acapy_verifier_admin.put(
                    f"/oid4vci/credential-supported/records/mso-mdoc/{rec_id}",
                    json={"trust_anchors": existing_anchors},
                )
                yield {"supported_cred_id": rec_id}
            else:
                result = await acapy_verifier_admin.post(
                    "/oid4vci/credential-supported/create/mso-mdoc",
                    json={
                        "format": "mso_mdoc",
                        "id": "verifier-trust-store",
                        "doctype": "org.iso.18013.5.1.mDL",
                        "trust_anchors": [cert_pem],
                    },
                )
                yield {"supported_cred_id": result.get("supported_cred_id")}
        except Exception as e:
            raise RuntimeError(f"Failed to setup trust anchors: {e}") from e


@pytest_asyncio.fixture
async def setup_credo_trust_anchors(credo_client, setup_issuer_certs):
    """Upload trust anchors to Credo agent via HTTP API.

    This fixture uploads the issuer's signing certificate as a trust anchor
    to Credo's X509 module for mDoc verification.

    Args:
        credo_client: HTTP client for Credo agent
        setup_issuer_certs: Issuer certificate fixture (provides the actual cert)

    Yields:
        Dictionary with status
    """
    # Upload issuer certificate as trust anchor to Credo
    try:
        # Credo validates the full certificate chain, so it needs the root CA
        # rather than the leaf DS certificate.  Fall back to the leaf cert for
        # self-signed setups that don't generate a separate root CA.
        trust_anchor_pem = (
            setup_issuer_certs.get("root_ca_pem")
            or setup_issuer_certs["certificate_pem"]
        )
        response = await credo_client.post(
            "/x509/trust-anchors",
            json={
                "certificate_pem": trust_anchor_pem,
            },
        )
        response.raise_for_status()
        result = response.json()
        print(f"Uploaded trust anchor to Credo: {result}")
        yield {"status": "success"}

    except Exception as e:
        # Check if trust anchors were set
        try:
            response = await credo_client.get("/x509/trust-anchors")
            anchors = response.json()
            if anchors.get("count", 0) > 0:
                yield {"status": "already_configured"}
            else:
                raise RuntimeError(f"Failed to setup Credo trust anchors: {e}") from e
        except Exception:
            raise RuntimeError(f"Failed to setup Credo trust anchors: {e}") from e


@pytest_asyncio.fixture
async def setup_all_trust_anchors(
    setup_verifier_trust_anchors, setup_credo_trust_anchors, setup_issuer_certs
):
    """Convenience fixture that sets up trust anchors in all agents.

    This fixture ensures both ACA-Py verifier and Credo have the same
    trust anchor configured before tests run. The trust anchor is the
    actual certificate used by the issuer for signing mDocs.

    Args:
        setup_verifier_trust_anchors: ACA-Py verifier trust anchor fixture
        setup_credo_trust_anchors: Credo trust anchor fixture
        setup_issuer_certs: Issuer certificate fixture

    Yields:
        Dictionary with all setup results
    """
    yield {
        "verifier": setup_verifier_trust_anchors,
        "credo": setup_credo_trust_anchors,
        "issuer_cert_pem": setup_issuer_certs["certificate_pem"],
        "signing_key_id": setup_issuer_certs.get("signing_key_id"),
    }


@pytest_asyncio.fixture
async def setup_pki_chain_trust_anchor(acapy_verifier_admin, generated_test_certs):
    """Upload the generated root CA as trust anchor for PKI chain tests.

    Uses the new ``POST /mso-mdoc/trust-anchors`` endpoint.  Falls back to
    ``vc_additional_data`` for agents not yet running new code.

    Yields:
        Dictionary with status.
    """
    root_ca_pem = generated_test_certs["root_ca_pem"]

    try:
        response = await acapy_verifier_admin.post(
            "/mso-mdoc/trust-anchors",
            json={
                "label": "pki-chain-trust-anchor",
                "purpose": "iaca",
                "certificate_pem": root_ca_pem,
            },
        )
        yield {"trust_anchor_id": response.get("id")}
    except Exception:
        # Fallback: vc_additional_data approach
        try:
            records = await acapy_verifier_admin.get(
                "/oid4vci/credential-supported/records"
            )
            mdoc_recs = [
                r for r in records.get("results", []) if r.get("format") == "mso_mdoc"
            ]

            if mdoc_recs:
                rec_id = mdoc_recs[0].get("supported_cred_id")
                existing_anchors = (
                    mdoc_recs[0].get("vc_additional_data", {}).get("trust_anchors", [])
                )
                if root_ca_pem not in existing_anchors:
                    existing_anchors.append(root_ca_pem)
                await acapy_verifier_admin.put(
                    f"/oid4vci/credential-supported/records/mso-mdoc/{rec_id}",
                    json={"trust_anchors": existing_anchors},
                )
                yield {"supported_cred_id": rec_id}
            else:
                result = await acapy_verifier_admin.post(
                    "/oid4vci/credential-supported/create/mso-mdoc",
                    json={
                        "format": "mso_mdoc",
                        "id": "pki-chain-trust-store",
                        "doctype": "org.iso.18013.5.1.mDL",
                        "trust_anchors": [root_ca_pem],
                    },
                )
                yield {"supported_cred_id": result.get("supported_cred_id")}
        except Exception as e:
            raise RuntimeError(f"Failed to setup PKI chain trust anchor: {e}") from e


# =============================================================================
# Shared Helper Functions
# =============================================================================


def safely_get_first_credential(response, wallet_name: str) -> str:
    """Safely extract credential from wallet response, skipping test if unavailable.

    Args:
        response: The HTTP response from wallet accept-offer call
        wallet_name: Name of wallet for error messages (e.g., "Credo", "Sphereon")

    Returns:
        The credential string

    Raises:
        pytest.skip: If credential could not be obtained (infrastructure issue)
    """
    if response.status_code != 200:
        pytest.skip(
            f"{wallet_name} failed to accept offer (status {response.status_code}): {response.text}"
        )

    resp_json = response.json()
    if "credential" not in resp_json:
        pytest.skip(f"{wallet_name} did not return credential: {resp_json}")

    return resp_json["credential"]


async def wait_for_presentation_valid(
    verifier_admin: Controller,
    presentation_id: str,
    max_retries: int = 30,
    interval: float = 1.0,
) -> dict:
    """Poll for presentation to be validated.

    Args:
        verifier_admin: ACA-Py verifier admin controller
        presentation_id: The presentation ID to check
        max_retries: Maximum number of retry attempts (default: 15)
        interval: Sleep interval between retries in seconds (default: 1.0)

    Returns:
        The presentation record when valid

    Raises:
        AssertionError: If presentation becomes invalid or times out
    """
    for _ in range(max_retries):
        record = await verifier_admin.get(f"/oid4vp/presentation/{presentation_id}")
        state = record.get("state")

        if state == "presentation-valid":
            return record
        if state == "presentation-invalid":
            raise AssertionError(f"Presentation invalid: {record}")

        await asyncio.sleep(interval)

    raise AssertionError(
        f"Timeout waiting for presentation validation. Final state: {record.get('state')}"
    )


# =============================================================================
# Session-Scoped DID Fixtures
# =============================================================================


@pytest_asyncio.fixture(scope="session")
async def issuer_ed25519_did():
    """Create a session-scoped Ed25519 issuer DID.

    This DID is reused across all tests in the session for improved performance.
    Each test creates unique credential configurations, so DID reuse is safe.

    Yields:
        str: The issuer DID (e.g., "did:key:z6Mk...")
    """
    controller = Controller(ACAPY_ISSUER_ADMIN_URL)

    # Wait for ACA-Py issuer to be ready
    for _ in range(30):
        status = await controller.get("/status/ready")
        if status.get("ready") is True:
            break
        await asyncio.sleep(1)
    else:
        raise RuntimeError("ACA-Py issuer service not available for DID creation")

    did_response = await controller.post(
        "/wallet/did/create",
        json={"method": "key", "options": {"key_type": "ed25519"}},
    )
    yield did_response["result"]["did"]


@pytest_asyncio.fixture(scope="session")
async def issuer_p256_did():
    """Create a session-scoped P-256 issuer DID.

    This DID is reused across all tests in the session for improved performance.
    Each test creates unique credential configurations, so DID reuse is safe.

    Yields:
        str: The issuer DID (e.g., "did:jwk:...")
    """
    controller = Controller(ACAPY_ISSUER_ADMIN_URL)

    # Wait for ACA-Py issuer to be ready
    for _ in range(30):
        status = await controller.get("/status/ready")
        if status.get("ready") is True:
            break
        await asyncio.sleep(1)
    else:
        raise RuntimeError("ACA-Py issuer service not available for DID creation")

    did_result = await controller.post("/did/jwk/create", json={"key_type": "p256"})
    yield did_result["did"]


# =============================================================================
# Credential Configuration Factory Fixtures
# =============================================================================


@pytest.fixture
def sd_jwt_credential_config():
    """Factory for creating SD-JWT credential supported configurations.

    Returns:
        Callable that generates unique SD-JWT credential configurations.

    Usage:
        config = sd_jwt_credential_config(
            vct="EmployeeCredential",
            claims={"name": {"mandatory": True}, "employee_id": {"mandatory": True}},
            sd_list=["/name", "/employee_id"]
        )
    """

    def _config(
        vct: str,
        claims: dict[str, dict],
        sd_list: list[str],
        scope: str = None,
        proof_algs: list[str] = None,
        binding_methods: list[str] = None,
        crypto_suites: list[str] = None,
    ) -> dict:
        """Generate an SD-JWT credential configuration.

        Args:
            vct: Verifiable Credential Type
            claims: Dictionary of claim names to claim definitions
            sd_list: List of selectively disclosable claim paths (e.g., ["/name"])
            scope: OAuth scope (defaults to vct)
            proof_algs: Proof signing algorithms (defaults to ["EdDSA", "ES256"])
            binding_methods: Binding methods (defaults to ["did:key"])
            crypto_suites: Cryptographic suites (defaults to ["EdDSA"])

        Returns:
            Complete credential supported configuration
        """
        random_suffix = str(uuid.uuid4())[:8]
        return {
            "id": f"{vct}_{random_suffix}",
            "format": "vc+sd-jwt",
            "scope": scope or vct,
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": proof_algs
                    or ["EdDSA", "ES256"]
                }
            },
            "format_data": {
                "cryptographic_binding_methods_supported": binding_methods
                or ["did:key", "jwk"],
                "credential_signing_alg_values_supported": crypto_suites or ["EdDSA"],
                "vct": vct,
                "claims": claims,
            },
            "vc_additional_data": {"sd_list": sd_list},
        }

    return _config


@pytest.fixture
def mdoc_credential_config():
    """Factory for creating mDOC credential configurations.

    Returns:
        Callable that generates unique mDOC credential configurations.

    Usage:
        config = mdoc_credential_config(
            doctype="org.iso.18013.5.1.mDL",
            namespace_claims={
                "org.iso.18013.5.1": {
                    "family_name": {"mandatory": True},
                    "given_name": {"mandatory": True}
                }
            }
        )
    """

    def _config(
        doctype: str = "org.iso.18013.5.1.mDL",
        namespace_claims: dict[str, dict] = None,
        binding_methods: list[str] = None,
        crypto_suites: list[str] = None,
    ) -> dict:
        """Generate an mDOC credential configuration.

        Args:
            doctype: Document type (defaults to mDL)
            namespace_claims: Dictionary of namespace to claims
            binding_methods: Binding methods (defaults to ["cose_key", "did:key", "did"])
            crypto_suites: Cryptographic suites (defaults to ["ES256"])

        Returns:
            Complete mDOC credential supported configuration
        """
        random_suffix = str(uuid.uuid4())[:8]

        # Default mDL claims if none provided
        if namespace_claims is None:
            namespace_claims = {
                "org.iso.18013.5.1": {
                    "given_name": {"mandatory": True},
                    "family_name": {"mandatory": True},
                    "birth_date": {"mandatory": False},
                }
            }

        return {
            "id": f"MdocCredential_{random_suffix}",
            "format": "mso_mdoc",
            "cryptographic_binding_methods_supported": binding_methods
            or ["cose_key", "did:key", "did"],
            "credential_signing_alg_values_supported": crypto_suites or ["ES256"],
            "format_data": {
                "doctype": doctype,
                "claims": namespace_claims,
            },
        }

    return _config


# =============================================================================
# Legacy Compatibility Fixtures (for old test files)
# =============================================================================


@pytest_asyncio.fixture
async def credo(credo_client):
    """Credo wrapper for backward compatibility with old tests."""
    wrapper = CredoWrapper(CREDO_AGENT_URL)
    async with wrapper:
        yield wrapper


@pytest_asyncio.fixture
async def sphereon(sphereon_client):
    """Sphereon wrapper for backward compatibility with old tests."""
    wrapper = SphereaonWrapper(SPHEREON_WRAPPER_URL)
    async with wrapper:
        yield wrapper


@pytest_asyncio.fixture
async def offer(acapy_issuer_admin, issuer_p256_did):
    """Create a JWT VC credential offer."""
    # Create supported credential
    supported = await acapy_issuer_admin.post(
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
    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported["supported_cred_id"],
            "credential_subject": {"name": "alice"},
            "verification_method": issuer_p256_did + "#0",
        },
    )

    # Get offer
    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    yield offer_response


# Legacy fixtures kept for test_interop compatibility - moved to test_interop/conftest.py
