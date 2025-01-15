"""Custom exceptions for Webvh DID registration."""


class DidCreationError(Exception):
    """Exception for DID creation errors."""

    pass


class DidUpdateError(Exception):
    """Exception for DID creation errors."""

    pass


class EndorsementSetupError(Exception):
    """Exception for endorsement setup errors."""

    pass


class EndorsementError(Exception):
    """Exception for endorsement errors."""

    pass


class ConfigurationError(Exception):
    """Exception for server connection errors."""

    pass
