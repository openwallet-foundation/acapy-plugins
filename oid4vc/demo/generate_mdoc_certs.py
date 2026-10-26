#!/usr/bin/env python3
"""Generate a TEST-ONLY mdoc IACA root and document signer for the demos.

ISO/IEC 18013-5 Annex B profiles:

- IACA root: self-signed, subject with C and CN, basicConstraints CA:TRUE
  pathlen 0 (critical), keyUsage keyCertSign + cRLSign (critical), subject key
  identifier, issuer alternative name, CRL distribution point; validity
  10 years (the profile allows up to 20).
- Document signer (DS): issued by the IACA, keyUsage digitalSignature
  (critical), extendedKeyUsage mdlDS 1.0.18013.5.1.2 (critical), authority and
  subject key identifiers, issuer alternative name, CRL distribution point;
  validity 1 year (the profile allows up to 457 days).

The demo imports the DS certificate and key as the mdoc signing key, so the
mdoc x5chain carries only the DS certificate, and registers the IACA as the
trust anchor. Give the IACA certificate to verifiers and test suites as the
trust anchor.

Prints JavaScript constants for demo/frontend/index.js. Needs ``cryptography``.
"""

import datetime
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

MDL_DS_EKU = ObjectIdentifier("1.0.18013.5.1.2")
ISSUER_ALT_NAME = x509.UniformResourceIdentifier("https://issuer.example.com")
CRL_URL = "https://issuer.example.com/crl"


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACA-Py OID4VC Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _crl() -> x509.CRLDistributionPoints:
    return x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(CRL_URL)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def generate():
    """Return (iaca_cert, ds_cert, ds_key)."""
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)

    iaca_key = ec.generate_private_key(ec.SECP256R1())
    iaca_name = _name("ACA-Py OID4VC Demo IACA (TEST ONLY)")
    iaca_ski = x509.SubjectKeyIdentifier.from_public_key(iaca_key.public_key())
    iaca = (
        x509.CertificateBuilder()
        .subject_name(iaca_name)
        .issuer_name(iaca_name)
        .public_key(iaca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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
        .add_extension(iaca_ski, critical=False)
        .add_extension(x509.IssuerAlternativeName([ISSUER_ALT_NAME]), critical=False)
        .add_extension(_crl(), critical=False)
        .sign(iaca_key, hashes.SHA256())
    )

    ds_key = ec.generate_private_key(ec.SECP256R1())
    ds = (
        x509.CertificateBuilder()
        .subject_name(_name("ACA-Py OID4VC Demo Document Signer (TEST ONLY)"))
        .issuer_name(iaca_name)
        .public_key(ds_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
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
        .add_extension(x509.ExtendedKeyUsage([MDL_DS_EKU]), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(iaca_ski),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ds_key.public_key()),
            critical=False,
        )
        .add_extension(x509.IssuerAlternativeName([ISSUER_ALT_NAME]), critical=False)
        .add_extension(_crl(), critical=False)
        .sign(iaca_key, hashes.SHA256())
    )
    return iaca, ds, ds_key


def main():
    """Print the demo constants."""
    iaca, ds, ds_key = generate()
    ds_key_pem = ds_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    expiry = f"{ds.not_valid_after_utc:%Y-%m-%d}"
    print(f"// Generated by demo/generate_mdoc_certs.py; DS valid until {expiry}.")
    print(f"const iaca_certificate_pem = {json.dumps(_pem(iaca))};")
    print(f"const certificate_pem = {json.dumps(_pem(ds))};")
    print(f"const private_key_pem = {json.dumps(ds_key_pem)};")


if __name__ == "__main__":
    main()
