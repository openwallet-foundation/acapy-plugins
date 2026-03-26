"""
ACA-Py Setup Script for OpenID Conformance Tests.

Configures ACA-Py issuer and verifier services with the necessary DIDs,
credential configurations, trust anchors, and credential offers before
the conformance suite begins testing.

Outputs a JSON file with dynamic configuration values (DID identifiers,
offer URIs, request URIs) that the conformance test runner consumes
to build the final conformance suite configuration.
"""

import asyncio
import base64
import datetime
import json
import logging
import os
import uuid
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePublicNumbers,
)
from cryptography.x509.oid import NameOID

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

ISSUER_ADMIN_URL = os.environ.get("ACAPY_ISSUER_ADMIN_URL", "http://acapy-issuer:8021")
ISSUER_OID4VCI_URL = os.environ.get(
    "ACAPY_ISSUER_OID4VCI_URL", "http://acapy-issuer:8022"
)
VERIFIER_ADMIN_URL = os.environ.get(
    "ACAPY_VERIFIER_ADMIN_URL", "http://acapy-verifier:8031"
)
VERIFIER_OID4VP_URL = os.environ.get(
    "ACAPY_VERIFIER_OID4VP_URL", "http://acapy-verifier:8032"
)
OUTPUT_FILE = os.environ.get("CONFORMANCE_SETUP_OUTPUT", "/tmp/conformance-setup.json")

POLL_INTERVAL = 2.0
POLL_MAX_ATTEMPTS = 60

# The conformance suite's hardcoded document signer certificate (from
# TestAppUtils.kt / VciMdocUtils.kt in openid/conformance-suite). When the
# suite acts as an mDL wallet (VP verifier tests), it signs mDL IssuerAuth
# with this key/cert regardless of any `credential.signing_jwk` config.
# The ACA-Py verifier must trust this cert so it can validate presented mDLs.
CONFORMANCE_SUITE_MDL_DS_CERT_PEM = b"""\
-----BEGIN CERTIFICATE-----
MIICqTCCAlCgAwIBAgIUEmctHgzxSGqk6Z8Eb+0s97VZdpowCgYIKoZIzj0EAwIw
gYcxCzAJBgNVBAYTAlVTMRgwFgYDVQQIDA9TdGF0ZSBvZiBVdG9waWExEjAQBgNV
BAcMCVNhbiBSYW1vbjEaMBgGA1UECgwRT3BlbklEIEZvdW5kYXRpb24xCzAJBgNV
BAsMAklUMSEwHwYDVQQDDBhjZXJ0aWZpY2F0aW9uLm9wZW5pZC5uZXQwHhcNMjUw
NzMwMDc0NzIyWhcNMjYwNzMwMDc0NzIyWjCBhzELMAkGA1UEBhMCVVMxGDAWBgNV
BAgMD1N0YXRlIG9mIFV0b3BpYTESMBAGA1UEBwwJU2FuIFJhbW9uMRowGAYDVQQK
DBFPcGVuSUQgRm91bmRhdGlvbjELMAkGA1UECwwCSVQxITAfBgNVBAMMGGNlcnRp
ZmljYXRpb24ub3BlbmlkLm5ldDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ5o
lgDBiHqNhN7rFkSy/xD34dQcOSR4KvEWMyb62jI+UGUofeAi/55RIt74pBsQz9+B
48WXI8xhIphoNN7AejajgZcwgZQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8B
Af8EBAMCAQYwIQYDVR0SBBowGIEWY2VydGlmaWNhdGlvbkBvaWRmLm9yZzAsBgNV
HR8EJTAjMCGgH6AdhhtodHRwOi8vZXhhbXBsZS5jb20vbXljYS5jcmwwHQYDVR0O
BBYEFHhk9LVVH8Gt9ZgfxgyhSl921XOhMAoGCCqGSM49BAMCA0cAMEQCICBxjCq9
efAwMKREK+k0OXBtiQCbFD7QdpyH42LVYfdvAiAurlZwp9PtmQZzoSYDUvXpZM5v
TvFLVc4ESGy3AtdC+g==
-----END CERTIFICATE-----
"""


async def wait_for_service(url: str, name: str) -> None:
    """Poll a service health endpoint until it responds."""
    health_url = f"{url}/status/live"
    logger.info(f"Waiting for {name} at {health_url} ...")
    async with httpx.AsyncClient() as client:
        for attempt in range(1, POLL_MAX_ATTEMPTS + 1):
            try:
                resp = await client.get(health_url, timeout=5.0)
                if resp.status_code < 500:
                    logger.info(f"{name} is healthy after {attempt} attempt(s)")
                    return
            except httpx.RequestError:
                pass
            if attempt < POLL_MAX_ATTEMPTS:
                await asyncio.sleep(POLL_INTERVAL)
    raise RuntimeError(f"{name} did not become healthy at {url}")


async def admin_get(client: httpx.AsyncClient, base: str, path: str) -> Any:
    """GET from ACA-Py admin API."""
    resp = await client.get(f"{base}{path}", timeout=30.0)
    resp.raise_for_status()
    return resp.json()


async def admin_post(
    client: httpx.AsyncClient, base: str, path: str, body: dict | None = None
) -> Any:
    """POST to ACA-Py admin API."""
    resp = await client.post(f"{base}{path}", json=body or {}, timeout=30.0)
    resp.raise_for_status()
    return resp.json()


async def admin_put(
    client: httpx.AsyncClient, base: str, path: str, body: dict | None = None
) -> Any:
    """PUT to ACA-Py admin API."""
    resp = await client.put(f"{base}{path}", json=body or {}, timeout=30.0)
    resp.raise_for_status()
    return resp.json()


async def create_did_jwk(client: httpx.AsyncClient, base: str, key_type: str) -> str:
    """Create a did:jwk and return the DID string."""
    result = await admin_post(client, base, "/did/jwk/create", {"key_type": key_type})
    did = result.get("did") or result.get("result", {}).get("did")
    if not did:
        raise RuntimeError(f"No DID in response: {result}")
    logger.info(f"Created did:jwk ({key_type}): {did}")
    return did


async def create_sd_jwt_credential_config(
    client: httpx.AsyncClient,
    base: str,
    issuer_did: str,
    *,
    x5c_cert_chain: list[str] | None = None,
) -> dict:
    """Register an SD-JWT VC credential configuration in ACA-Py.

    Args:
        x5c_cert_chain: If provided, adds an x5c header to issued SD-JWT
            credentials (required by HAIP/OIDF conformance).
    """
    config_id = f"conformance-sdjwt-{uuid.uuid4().hex[:8]}"
    payload = {
        "id": config_id,
        "format": "dc+sd-jwt",
        "scope": config_id,
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["EdDSA", "ES256"]}
        },
        "display": [{"name": "Identity Credential", "locale": "en"}],
        "format_data": {
            "vct": "https://credentials.example.com/identity_credential",
            "cryptographic_binding_methods_supported": ["did:key", "jwk"],
            # credential_signing_alg_values_supported belongs at the credential
            # config level (not inside format_data), and is handled by the model.
            # Do NOT add cryptographic_suites_supported here — it is deprecated
            # in OID4VCI 1.0 and causes "invalid entries" in conformance tests.
            "claims": {
                "given_name": {"display": [{"name": "Given Name", "locale": "en"}]},
                "family_name": {"display": [{"name": "Family Name", "locale": "en"}]},
                "email": {"display": [{"name": "Email", "locale": "en"}]},
                "birthdate": {"display": [{"name": "Date of Birth", "locale": "en"}]},
            },
        },
        "vc_additional_data": {
            "sd_list": [
                "/given_name",
                "/family_name",
                "/email",
                "/birthdate",
            ],
            **({"x5c_cert_chain": x5c_cert_chain} if x5c_cert_chain else {}),
        },
    }
    result = await admin_post(
        client, base, "/oid4vci/credential-supported/create", payload
    )
    supported_cred_id = result.get("supported_cred_id")
    if not supported_cred_id:
        raise RuntimeError(f"No supported_cred_id in response: {result}")
    logger.info(f"Created SD-JWT credential config: {config_id} → {supported_cred_id}")
    return {
        "config_id": config_id,
        "supported_cred_id": supported_cred_id,
        "issuer_did": issuer_did,
    }


async def create_mdoc_credential_config(
    client: httpx.AsyncClient, base: str, issuer_did: str
) -> dict:
    """Register an mDOC/mDL credential configuration in ACA-Py."""
    config_id = f"conformance-mdoc-{uuid.uuid4().hex[:8]}"
    payload = {
        "id": config_id,
        "format": "mso_mdoc",
        "display": [{"name": "Mobile Driver's License", "locale": "en"}],
        "cryptographic_binding_methods_supported": ["cose_key"],
        # Store as JOSE string — to_issuer_metadata() converts it to the COSE
        # integer identifier (-7) required by the OID4VCI metadata spec for mso_mdoc.
        "cryptographic_suites_supported": ["ES256"],
        "format_data": {
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
                "org.iso.18013.5.1": {
                    "given_name": {
                        "display": [{"name": "Given Name", "locale": "en"}],
                        "mandatory": True,
                    },
                    "family_name": {
                        "display": [{"name": "Family Name", "locale": "en"}],
                        "mandatory": True,
                    },
                    "birth_date": {
                        "display": [{"name": "Date of Birth", "locale": "en"}],
                        "mandatory": True,
                    },
                    "document_number": {
                        "display": [{"name": "Document Number", "locale": "en"}],
                        "mandatory": False,
                    },
                }
            },
        },
    }
    result = await admin_post(
        client, base, "/oid4vci/credential-supported/create", payload
    )
    supported_cred_id = result.get("supported_cred_id")
    if not supported_cred_id:
        raise RuntimeError(f"No supported_cred_id in response: {result}")
    logger.info(f"Created mDOC credential config: {config_id} → {supported_cred_id}")
    return {
        "config_id": config_id,
        "supported_cred_id": supported_cred_id,
        "issuer_did": issuer_did,
    }


async def create_credential_offer(
    client: httpx.AsyncClient,
    base: str,
    credential_config_id: str,
    issuer_did: str,
    pin: str | None = None,
    credential_subject: dict | None = None,
) -> dict:
    """Create a pre-authorized credential offer and return offer details."""
    if credential_subject is None:
        credential_subject = {
            "given_name": "Alice",
            "family_name": "Smith",
            "email": "alice@example.com",
            "birthdate": "1990-01-15",
        }
    exchange_body: dict[str, Any] = {
        "supported_cred_id": credential_config_id,
        "credential_subject": credential_subject,
        # verification_method format: {did}#0  (selects the first key on the DID)
        "verification_method": f"{issuer_did}#0",
    }
    if pin is not None:
        exchange_body["pin"] = pin
    exchange_result = await admin_post(
        client,
        base,
        "/oid4vci/exchange/create",
        exchange_body,
    )
    exchange_id = exchange_result.get("exchange_id") or exchange_result.get("id")
    if not exchange_id:
        raise RuntimeError(f"No exchange_id in response: {exchange_result}")

    offer_result = await admin_get(
        client, base, f"/oid4vci/credential-offer?exchange_id={exchange_id}"
    )
    offer_uri = offer_result.get("offer_uri") or offer_result.get("credential_offer")
    if not offer_uri:
        raise RuntimeError(f"No offer_uri in response: {offer_result}")

    logger.info(f"Created credential offer for {credential_config_id}: {offer_uri}")
    return {
        "exchange_id": exchange_id,
        "offer_uri": offer_uri,
        "credential_config_id": credential_config_id,
    }


def _generate_test_pki() -> tuple[bytes, bytes, bytes]:
    """Generate a minimal PKI chain (root CA → DS cert) for mDOC trust testing.

    Returns (root_cert_pem, ds_cert_pem, ds_key_pem).
    """
    now = datetime.datetime.utcnow()

    # Root CA key + cert
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Conformance Test Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Conformance"),
        ]
    )
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
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
        .sign(root_key, hashes.SHA256())
    )

    # DS (Document Signer) key + cert
    ds_key = ec.generate_private_key(ec.SECP256R1())
    ds_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Conformance Test DS"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Conformance"),
        ]
    )
    ds_cert = (
        x509.CertificateBuilder()
        .subject_name(ds_name)
        .issuer_name(root_name)
        .public_key(ds_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    return (
        root_cert.public_bytes(serialization.Encoding.PEM),
        ds_cert.public_bytes(serialization.Encoding.PEM),
        ds_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )


def _ec_pub_key_from_jwk(jwk: dict):
    """Reconstruct a P-256 EC public key from a JWK dict."""

    # Pad base64url to a multiple of 4
    def _b64(s: str):
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)

    x = int.from_bytes(_b64(jwk["x"]), "big")
    y = int.from_bytes(_b64(jwk["y"]), "big")
    return EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256R1()).public_key()


def _pem_cert_chain_to_b64der(cert_chain_pem: bytes) -> list[str]:
    """Convert a PEM certificate chain to a list of base64(DER) strings.

    Strips PEM headers/footers and whitespace to produce the ``x5c`` array
    format required by RFC 7517 §4.7 (standard base64, leaf first).
    """
    import re as _re

    return [
        _re.sub(r"\s+", "", cert)
        for cert in _re.findall(
            r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
            cert_chain_pem.decode(),
            _re.DOTALL,
        )
    ]


def _generate_verifier_pki(dns_name: str, did_jwk_str: str) -> tuple[bytes, bytes]:
    """Generate a verifier certificate with dNSName SAN matching *dns_name*.

    The leaf certificate's public key is extracted from the ``did:jwk:`` DID
    so that a JWT signed by ACA-Py using that DID's private key will validate
    against the x5c leaf cert.

    Returns (combined_pem, leaf_cert_pem) where combined_pem is a PEM string
    with the leaf cert followed by the root CA cert — suitable for uploading
    to ``POST /oid4vp/x509-identity``.
    """
    # Decode JWK from did:jwk identifier.
    b64 = did_jwk_str[len("did:jwk:") :]
    b64 += "=" * (-len(b64) % 4)
    jwk = json.loads(base64.urlsafe_b64decode(b64))
    leaf_pub_key = _ec_pub_key_from_jwk(jwk)

    now = datetime.datetime.utcnow()

    # Generate a short-lived root CA to sign the leaf.
    root_key = ec.generate_private_key(SECP256R1())
    root_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Conformance Verifier Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Conformance"),
        ]
    )
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
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
        .sign(root_key, hashes.SHA256())
    )

    # Leaf cert: public key from did:jwk + dNSName SAN.
    leaf_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, dns_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Conformance"),
        ]
    )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(leaf_pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns_name)]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
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
        .sign(root_key, hashes.SHA256())
    )

    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    root_pem = root_cert.public_bytes(serialization.Encoding.PEM)
    # combined PEM: leaf first, then root CA (matches x5c ordering per RFC 7517 §4.7)
    return leaf_pem + root_pem, leaf_pem


async def register_x509_identity(
    client: httpx.AsyncClient,
    base: str,
    cert_chain_pem: bytes,
    verification_method: str,
    client_id: str,
) -> dict:
    """Register the X.509 identity for the OID4VP verifier."""
    result = await admin_post(
        client,
        base,
        "/oid4vp/x509-identity",
        {
            "cert_chain_pem": cert_chain_pem.decode(),
            "verification_method": verification_method,
            "client_id": client_id,
        },
    )
    logger.info(f"Registered x509 identity: client_id={client_id}")
    return result


async def upload_trust_anchor(
    client: httpx.AsyncClient,
    base: str,
    cert_pem: bytes,
    *,
    anchor_type: str = "mso_mdoc",
    supported_cred_id: str | None = None,
    label: str | None = None,
) -> None:
    """Upload a trust anchor certificate to an ACA-Py instance.

    Trust anchors are stored as TrustAnchorRecord objects in the Askar wallet
    and retrieved at verification time via the /mso-mdoc/trust-anchors registry.
    The supported_cred_id parameter is accepted for backward compatibility but
    is no longer used; anchors are tenant-scoped, not credential-scoped.
    """
    cert_str = cert_pem.decode()
    await admin_post(
        client,
        base,
        "/mso-mdoc/trust-anchors",
        {
            "certificate_pem": cert_str,
            "purpose": "iaca",
            "label": label or anchor_type,
        },
    )
    logger.info(f"Uploaded trust anchor to {base} ({anchor_type})")


async def create_vp_presentation_definition(
    client: httpx.AsyncClient, base: str, credential_type: str
) -> dict:
    """Create a presentation definition for OID4VP conformance testing."""
    pres_def_id = f"conformance-pd-{uuid.uuid4().hex[:8]}"
    if credential_type == "sdjwt":
        payload = {
            "pres_def": {
                "id": pres_def_id,
                "input_descriptors": [
                    {
                        "id": "identity-credential",
                        "name": "Identity Credential",
                        "purpose": "To verify your identity",
                        "format": {"vc+sd-jwt": {"alg": ["EdDSA", "ES256"]}},
                        "constraints": {
                            "fields": [
                                {
                                    "path": ["$.vct"],
                                    "filter": {
                                        "type": "string",
                                        "const": "https://credentials.example.com/identity_credential",
                                    },
                                }
                            ]
                        },
                    }
                ],
            }
        }
    else:  # mdl
        payload = {
            "pres_def": {
                "id": pres_def_id,
                "input_descriptors": [
                    {
                        "id": "mdl-credential",
                        "name": "Mobile Driver's License",
                        "purpose": "To verify your identity",
                        "format": {"mso_mdoc": {"alg": ["ES256"]}},
                        "constraints": {
                            "fields": [
                                {
                                    "path": [
                                        "$['org.iso.18013.5.1']['given_name']",
                                        "$['org.iso.18013.5.1']['family_name']",
                                    ]
                                }
                            ]
                        },
                    }
                ],
            }
        }
    result = await admin_post(client, base, "/oid4vp/presentation-definition", payload)
    pres_def_record_id = result.get("id") or result.get("pres_def_id")
    logger.info(
        f"Created presentation definition ({credential_type}): {pres_def_record_id}"
    )
    return {"pres_def_id": pres_def_record_id, "definition_id": pres_def_id}


async def create_vp_request(
    client: httpx.AsyncClient,
    base: str,
    pres_def_id: str,
    *,
    vp_url: str,
) -> dict:
    """Create an OID4VP authorization request and return the request URI."""
    payload = {
        "pres_def_id": pres_def_id,
        "vp_formats": {
            "vc+sd-jwt": {"alg": ["EdDSA", "ES256"]},
            "mso_mdoc": {"alg": ["ES256"]},
        },
    }
    result = await admin_post(client, base, "/oid4vp/request", payload)
    request_uri = result.get("request_uri", "")
    request_id = (result.get("request") or {}).get("request_id") or (
        result.get("presentation") or {}
    ).get("request_id")
    presentation_id = (result.get("presentation") or {}).get("presentation_id")
    logger.info(f"Created VP request: {request_uri}")
    return {
        "request_id": request_id,
        "presentation_id": presentation_id,
        "request_uri": request_uri,
    }


async def create_sdjwt_dcql_query(
    client: httpx.AsyncClient,
    base: str,
) -> dict:
    """Create a DCQL query for SD-JWT VC (dc+sd-jwt) OID4VP conformance testing.

    OID4VP Final (1.0) requires DCQL for the oid4vp-1final-verifier-test-plan.
    The conformance suite (AbstractCreateSdJwtCredential) issues credentials
    with vct=urn:eudi:pid:1.
    """
    payload = {
        "credentials": [
            {
                "id": "pid_credential",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:1"]},
                "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                    {"path": ["birthdate"]},
                ],
            }
        ]
    }
    result = await admin_post(client, base, "/oid4vp/dcql/queries", payload)
    dcql_query_id = result.get("dcql_query_id") or (result.get("dcql_query") or {}).get(
        "dcql_query_id"
    )
    logger.info(f"Created DCQL query (sdjwt): {dcql_query_id}")
    return {"dcql_query_id": dcql_query_id}


async def create_mdl_dcql_query(
    client: httpx.AsyncClient,
    base: str,
) -> dict:
    """Create a DCQL query for mDL (iso_mdl) OID4VP conformance testing.

    The OID4VP Final (1.0) spec requires DCQL for requests that use
    credential_format=iso_mdl in the oid4vp-1final-verifier-test-plan.

    For mso_mdoc credentials, DCQL claims use path notation where the path
    is [namespace, claim_name] per the OID4VP Final spec and the conformance
    suite's DCQL validator.
    """
    payload = {
        "credentials": [
            {
                "id": "mdl_credential",
                "format": "mso_mdoc",
                "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                "claims": [
                    {"path": ["org.iso.18013.5.1", "given_name"]},
                    {"path": ["org.iso.18013.5.1", "family_name"]},
                    {"path": ["org.iso.18013.5.1", "birth_date"]},
                ],
            }
        ]
    }
    result = await admin_post(client, base, "/oid4vp/dcql/queries", payload)
    dcql_query_id = result.get("dcql_query_id") or (result.get("dcql_query") or {}).get(
        "dcql_query_id"
    )
    logger.info(f"Created DCQL query (mdl): {dcql_query_id}")
    return {"dcql_query_id": dcql_query_id}


async def create_vp_request_dcql(
    client: httpx.AsyncClient,
    base: str,
    dcql_query_id: str,
    *,
    vp_url: str,
    vp_formats: dict | None = None,
) -> dict:
    """Create an OID4VP authorization request using a DCQL query.

    Args:
        vp_formats: VP format constraints to include in the request. Defaults
            to mso_mdoc for backwards compatibility.
    """
    if vp_formats is None:
        vp_formats = {"mso_mdoc": {"alg": ["ES256"]}}
    payload = {
        "dcql_query_id": dcql_query_id,
        "vp_formats": vp_formats,
    }
    result = await admin_post(client, base, "/oid4vp/request", payload)
    request_uri = result.get("request_uri", "")
    request_id = (result.get("request") or {}).get("request_id") or (
        result.get("presentation") or {}
    ).get("request_id")
    presentation_id = (result.get("presentation") or {}).get("presentation_id")
    logger.info(f"Created VP request (DCQL): {request_uri}")
    return {
        "request_id": request_id,
        "presentation_id": presentation_id,
        "request_uri": request_uri,
    }


async def main() -> None:
    """Main setup flow."""
    logger.info("=== ACA-Py Conformance Test Setup ===")

    # Wait for services
    await wait_for_service(ISSUER_ADMIN_URL, "ACA-Py Issuer")
    await wait_for_service(VERIFIER_ADMIN_URL, "ACA-Py Verifier")

    setup_output: dict[str, Any] = {
        "issuer": {},
        "verifier": {},
    }

    async with httpx.AsyncClient() as client:
        # ── Issuer setup ────────────────────────────────────────────────────
        logger.info("--- Configuring Issuer ---")

        # Create DIDs
        ed25519_did = await create_did_jwk(client, ISSUER_ADMIN_URL, "ed25519")
        p256_did = await create_did_jwk(client, ISSUER_ADMIN_URL, "p256")
        # Separate P-256 DID for SD-JWT issuance — required for x5c cert binding.
        # HAIP [HAIP-6.1.1] mandates x5c in the SD-JWT VC header; the cert must
        # contain the issuer's public key and the signing must use P-256 (ES256).
        sdjwt_p256_did = await create_did_jwk(client, ISSUER_ADMIN_URL, "p256")

        # Generate a cert chain for the SD-JWT issuer (x5c header requirement).
        # The leaf cert embeds the sdjwt_p256_did's public key and uses the
        # issuer's external HTTPS domain as the dNSName SAN.
        issuer_dns_name = "acapy-tls-proxy.local"
        issuer_cert_pem, _ = _generate_verifier_pki(issuer_dns_name, sdjwt_p256_did)
        issuer_x5c_chain = _pem_cert_chain_to_b64der(issuer_cert_pem)

        # Register credential configs
        sdjwt_config = await create_sd_jwt_credential_config(
            client, ISSUER_ADMIN_URL, sdjwt_p256_did, x5c_cert_chain=issuer_x5c_chain
        )
        mdoc_config = await create_mdoc_credential_config(
            client, ISSUER_ADMIN_URL, p256_did
        )

        # Generate PKI for mDOC trust
        root_cert_pem, ds_cert_pem, _ds_key_pem = _generate_test_pki()

        # Upload issuer signing cert
        await upload_trust_anchor(
            client, ISSUER_ADMIN_URL, root_cert_pem, anchor_type="mso_mdoc"
        )

        # Create credential offers (pre-auth code)
        # A fixed tx_code (pin) is used so the conformance suite can use
        # "static_tx_code" in its config, bypassing the interactive tx_code
        # delivery step that would require polling.
        sdjwt_tx_code = "123456"
        sdjwt_offer = await create_credential_offer(
            client,
            ISSUER_ADMIN_URL,
            sdjwt_config["supported_cred_id"],
            sdjwt_p256_did,
            pin=sdjwt_tx_code,
        )
        mdoc_offer = await create_credential_offer(
            client,
            ISSUER_ADMIN_URL,
            mdoc_config["supported_cred_id"],
            p256_did,
            credential_subject={
                "family_name": "Smith",
                "given_name": "Alice",
                "birth_date": "1990-01-15",
                "issue_date": "2024-01-01",
                "expiry_date": "2029-01-01",
                "issuing_country": "US",
                "issuing_authority": "US DMV",
                "document_number": "DL-12345678",
                "portrait": "bXVzdGFjaGlv",
                "driving_privileges": [],
                "un_distinguishing_sign": "USA",
            },
        )

        setup_output["issuer"] = {
            "url": ISSUER_OID4VCI_URL,
            "admin_url": ISSUER_ADMIN_URL,
            "ed25519_did": ed25519_did,
            "p256_did": p256_did,
            "sdjwt_p256_did": sdjwt_p256_did,
            "sdjwt_credential_config_id": sdjwt_config["supported_cred_id"],
            "sdjwt_identifier": sdjwt_config["config_id"],
            "sdjwt_tx_code": sdjwt_tx_code,
            "mdoc_credential_config_id": mdoc_config["supported_cred_id"],
            "mdoc_identifier": mdoc_config["config_id"],
            "sdjwt_offer": sdjwt_offer,
            "mdoc_offer": mdoc_offer,
        }

        # ── Verifier setup ──────────────────────────────────────────────────
        logger.info("--- Configuring Verifier ---")

        # Upload trust anchor to verifier (for mDOC holder cert validation)
        await upload_trust_anchor(
            client, VERIFIER_ADMIN_URL, root_cert_pem, anchor_type="mso_mdoc"
        )
        # The conformance suite wallet signs mDL presentations with its own
        # hardcoded document signer cert (TestAppUtils.kt). Upload it so the
        # verifier trusts mDLs presented by the conformance suite during VP tests.
        await upload_trust_anchor(
            client,
            VERIFIER_ADMIN_URL,
            CONFORMANCE_SUITE_MDL_DS_CERT_PEM,
            anchor_type="mso_mdoc",
        )

        # Create presentation definitions (kept for backward-compat, but OID4VP
        # Final tests use DCQL now)
        sdjwt_pd = await create_vp_presentation_definition(
            client, VERIFIER_ADMIN_URL, "sdjwt"
        )
        # For OID4VP Final iso_mdl tests, the conformance suite requires DCQL.
        # We still create a presentation definition for backward-compat but the
        # actual mdl VP request uses a DCQL query.
        mdoc_pd = await create_vp_presentation_definition(
            client, VERIFIER_ADMIN_URL, "mdl"
        )
        # OID4VP Final (1.0) requires DCQL for both sd_jwt_vc and iso_mdl variants.
        sdjwt_dcql = await create_sdjwt_dcql_query(client, VERIFIER_ADMIN_URL)
        mdl_dcql = await create_mdl_dcql_query(client, VERIFIER_ADMIN_URL)

        # ── x509_san_dns identity for the verifier ──────────────────────────
        # The OIDF conformance suite requires client_id_scheme=x509_san_dns for
        # OID4VP verifier plans. We create a P-256 did:jwk for the verifier
        # signing key, generate a TLS-style leaf cert containing that public
        # key + a dNSName SAN, sign it with a fresh root CA, and register both
        # with ACA-Py so it includes x5c in request object JWTs.
        #
        # IMPORTANT: the DNS name must match the hostname in the conformance
        # suite's "verifier_url" (https://acapy-tls-proxy.local:8444) so the
        # suite can derive the expected client_id from the configuration and
        # compare it against the JAR's client_id field.
        verifier_dns_name = "acapy-tls-proxy.local"
        verifier_p256_did = await create_did_jwk(client, VERIFIER_ADMIN_URL, "p256")
        verifier_cert_pem, _leaf_pem = _generate_verifier_pki(
            verifier_dns_name, verifier_p256_did
        )
        await register_x509_identity(
            client,
            VERIFIER_ADMIN_URL,
            verifier_cert_pem,
            f"{verifier_p256_did}#0",
            verifier_dns_name,
        )
        logger.info(
            f"Verifier x509 identity registered: client_id={verifier_dns_name}, "
            f"vm={verifier_p256_did}#0"
        )

        # Create initial VP requests using DCQL (required by OID4VP Final conformance suite)
        sdjwt_vp_request = await create_vp_request_dcql(
            client,
            VERIFIER_ADMIN_URL,
            sdjwt_dcql["dcql_query_id"],
            vp_url=VERIFIER_OID4VP_URL,
            vp_formats={
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256"],
                    "kb-jwt_alg_values": ["ES256"],
                }
            },
        )
        # MDL request uses DCQL (required by OID4VP Final conformance suite)
        mdoc_vp_request = await create_vp_request_dcql(
            client,
            VERIFIER_ADMIN_URL,
            mdl_dcql["dcql_query_id"],
            vp_url=VERIFIER_OID4VP_URL,
        )

        setup_output["verifier"] = {
            "url": VERIFIER_OID4VP_URL,
            "admin_url": VERIFIER_ADMIN_URL,
            "p256_did": verifier_p256_did,
            "x509_dns_name": verifier_dns_name,
            "sdjwt_pres_def": sdjwt_pd,
            "mdoc_pres_def": mdoc_pd,
            "sdjwt_dcql": sdjwt_dcql,
            "mdl_dcql": mdl_dcql,
            "sdjwt_vp_request": sdjwt_vp_request,
            "mdoc_vp_request": mdoc_vp_request,
        }

    # Write output file
    with open(OUTPUT_FILE, "w") as f:
        json.dump(setup_output, f, indent=2)

    logger.info(f"Setup complete — output written to {OUTPUT_FILE}")
    logger.info(json.dumps(setup_output, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
