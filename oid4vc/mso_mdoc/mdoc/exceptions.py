"""Exceptions module."""


class MissingPrivateKey(Exception):
    """Missing private key error."""

    pass


class NoDocumentTypeProvided(Exception):
    """No document type error."""

    pass


class NoSignedDocumentProvided(Exception):
    """No signed document provider error."""

    pass


class MissingIssuerAuth(Exception):
    """Missing issuer authentication error."""

    pass
