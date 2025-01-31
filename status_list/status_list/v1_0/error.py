"""Status list errors."""

from acapy_agent.core.error import BaseError


class StatusListError(BaseError):
    """Status list errors."""


class DuplicateListNumberError(StatusListError):
    """Duplicate list number error."""
