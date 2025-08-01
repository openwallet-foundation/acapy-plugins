"""Custom exceptions for Webvh DID registration."""


class DidCreationError(Exception):
    """Exception for DID creation errors."""

    pass


class DidUpdateError(Exception):
    """Exception for DID creation errors."""

    pass


class ConfigurationError(Exception):
    """Exception for server connection errors."""

    pass


class OperationError(Exception):
    """Exception for did operation errors."""

    pass


class WitnessError(Exception):
    """Exception for witness errors."""

    pass
