"""X.509 certificate utilities."""

from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cwt import COSEKey
from pycose.keys import CoseKey
from pycose.keys.keytype import KtyOKP


def selfsigned_x509cert(private_key: CoseKey):
    """Generate a self-signed X.509 certificate from a COSE key."""
    ckey = COSEKey.from_bytes(private_key.encode())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Local CA"),
        ]
    )
    utcnow = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ckey.key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(utcnow)
        .not_valid_after(utcnow + timedelta(days=10))
        .sign(ckey.key, None if private_key.kty == KtyOKP else hashes.SHA256())
    )
    return cert.public_bytes(getattr(serialization.Encoding, "DER"))
