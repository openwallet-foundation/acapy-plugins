"""Certificate parsing, chain checks, and certificate selection."""

import base64
from datetime import datetime, timezone
from typing import List, Optional

from acapy_agent.core.profile import ProfileSession
from acapy_agent.wallet.keys.manager import verkey_to_multikey
from acapy_agent.wallet.util import bytes_to_b58
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .models import X509CertificateRecord


class X509Error(Exception):
    """Invalid certificate input or no usable certificate."""


def load_pem_chain(pem: str) -> List[x509.Certificate]:
    """Parse one or more PEM certificates, preserving order."""
    try:
        certs = x509.load_pem_x509_certificates(pem.encode())
    except ValueError as err:
        raise X509Error(f"Invalid PEM certificate: {err}") from err
    if not certs:
        raise X509Error("No certificate found in PEM")
    return certs


def load_x5c(x5c: List[str]) -> List[x509.Certificate]:
    """Parse an x5c list (standard base64 DER)."""
    if not x5c:
        raise X509Error("x5c is empty")
    try:
        return [x509.load_der_x509_certificate(base64.b64decode(c)) for c in x5c]
    except ValueError as err:
        raise X509Error(f"Invalid x5c certificate: {err}") from err


def to_x5c(certs: List[x509.Certificate]) -> List[str]:
    """Encode certificates as an x5c list."""
    return [base64.b64encode(c.public_bytes(Encoding.DER)).decode() for c in certs]


def to_pem(cert: x509.Certificate) -> str:
    """Encode a certificate as PEM."""
    return cert.public_bytes(Encoding.PEM).decode()


def pem_chain(x5c: List[str]) -> str:
    """Concatenated PEM for an x5c list, in the same order."""
    return "".join(to_pem(cert) for cert in load_x5c(x5c))


def is_issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Return whether `issuer` signed `cert`."""
    try:
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def is_self_signed(cert: x509.Certificate) -> bool:
    """Return whether the certificate signed itself."""
    return is_issued_by(cert, cert)


def check_chain_order(certs: List[x509.Certificate]):
    """Require each certificate to be signed by the next one."""
    for i in range(len(certs) - 1):
        if not is_issued_by(certs[i], certs[i + 1]):
            raise X509Error(f"Certificate {i} is not issued by certificate {i + 1}")


def public_key_multikey(cert: x509.Certificate) -> str:
    """Multikey of the certificate's P-256 or Ed25519 public key."""
    key = cert.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
        raw = key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        return verkey_to_multikey(bytes_to_b58(raw), alg="p256")
    if isinstance(key, ed25519.Ed25519PublicKey):
        raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return verkey_to_multikey(bytes_to_b58(raw), alg="ed25519")
    raise X509Error("Certificate key must be P-256 or Ed25519")


def subject_alt_names(cert: x509.Certificate) -> List[str]:
    """Return SANs as `type:value` strings."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    names = []
    for name in ext.value:
        if isinstance(name, x509.DNSName):
            names.append(f"dns:{name.value}")
        elif isinstance(name, x509.UniformResourceIdentifier):
            names.append(f"uri:{name.value}")
        elif isinstance(name, x509.RFC822Name):
            names.append(f"email:{name.value}")
    return names


def describe(cert: x509.Certificate) -> dict:
    """Parsed fields stored with records and returned by the API."""
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sans": subject_alt_names(cert),
    }


def embedded_x5c(record: X509CertificateRecord) -> List[str]:
    """The record's chain without a self-signed root, which HAIP forbids in x5c."""
    x5c = record.x5c
    if len(x5c) > 1 and is_self_signed(load_x5c(x5c[-1:])[0]):
        return x5c[:-1]
    return x5c


async def select_certificate(
    session: ProfileSession,
    multikey: str,
    purpose: str,
    expires_at: datetime,
    now: Optional[datetime] = None,
) -> X509CertificateRecord:
    """Pick the certificate valid from now through the credential's expiry.

    Among qualifying certificates, the earliest notAfter wins, then the
    earliest notBefore.
    """
    now = now or datetime.now(timezone.utc)
    records = await X509CertificateRecord.query(
        session, {"multikey": multikey, "purpose": purpose}
    )
    valid = [
        r
        for r in records
        if datetime.fromisoformat(r.not_before) <= now
        and datetime.fromisoformat(r.not_after) >= expires_at
    ]
    if not valid:
        raise X509Error(
            f"No {purpose} certificate for {multikey} is valid from now "
            f"until {expires_at.isoformat()}"
        )
    return min(
        valid,
        key=lambda r: (
            datetime.fromisoformat(r.not_after),
            datetime.fromisoformat(r.not_before),
        ),
    )
