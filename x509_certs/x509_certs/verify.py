"""Certificate chain verification against trust anchors."""

from datetime import datetime
from typing import List

from cryptography import x509

from .certs import X509Error, is_issued_by


def _check_validity(cert: x509.Certificate, at: datetime, label: str):
    if not cert.not_valid_before_utc <= at <= cert.not_valid_after_utc:
        raise X509Error(f"{label} is not valid at {at.isoformat()}")


def check_ca(cert: x509.Certificate, label: str):
    """Require the CA flag in basicConstraints."""
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        raise X509Error(f"{label} has no basicConstraints") from None
    if not constraints.value.ca:
        raise X509Error(f"{label} is not a CA")


def verify_chain(
    chain: List[x509.Certificate], anchors: List[x509.Certificate], at: datetime
) -> x509.Certificate:
    """Verify a leaf-first chain ends at one of `anchors`; return that anchor.

    Checks signatures, validity at `at`, and the CA flag on every issuer. The
    chain may end with the anchor itself or with a certificate it issued.
    """
    for i, cert in enumerate(chain):
        _check_validity(cert, at, f"Certificate {i}")
        if i > 0:
            check_ca(cert, f"Certificate {i}")
            if not is_issued_by(chain[i - 1], cert):
                raise X509Error(f"Certificate {i - 1} is not issued by certificate {i}")

    last = chain[-1]
    for anchor in anchors:
        if last == anchor:
            return anchor
    for anchor in anchors:
        if is_issued_by(last, anchor):
            _check_validity(anchor, at, "Trust anchor")
            check_ca(anchor, "Trust anchor")
            return anchor
    raise X509Error("Chain does not lead to a trust anchor for this purpose")
