"""MDoc module."""

from .issuer import mso_mdoc_sign, mdoc_sign
from .verifier import mso_mdoc_verify, mdoc_verify, MdocVerifyResult
from .exceptions import MissingPrivateKey, MissingIssuerAuth
from .exceptions import NoDocumentTypeProvided, NoSignedDocumentProvided

__all__ = [
    "mso_mdoc_sign",
    "mdoc_sign",
    "mso_mdoc_verify",
    "mdoc_verify",
    "MdocVerifyResult",
    "MissingPrivateKey",
    "MissingIssuerAuth",
    "NoDocumentTypeProvided",
    "NoSignedDocumentProvided",
]
