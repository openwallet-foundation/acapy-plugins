"""Custom exceptions for Webvh DID registration."""


class DidCreationError(Exception):
    """Exception for DID creation errors."""

    pass


class DidUpdateError(Exception):
    """Exception for DID creation errors."""

    pass


class WitnessSetupError(Exception):
    """Exception for witness setup errors."""

    pass


class WitnessError(Exception):
    """Exception for witness errors."""

    pass


class ConfigurationError(Exception):
    """Exception for server connection errors."""

    pass
