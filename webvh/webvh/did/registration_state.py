"""Enum for the registration state of a DID."""

from enum import Enum


class RegistrationState(Enum):
    """Enum for the registration state of a DID."""

    SUCCESS = "success"
    PENDING = "pending"
    ATTESTED = "attested"
    POSTED = "posted"
    FINISHED = "finished"
