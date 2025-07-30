"""States for witness protocols."""

from enum import Enum


class WitnessingState(Enum):
    """Enum for the attestation state of a DID."""

    SUCCESS = "success"
    PENDING = "pending"
    ATTESTED = "attested"
    POSTED = "posted"
    FINISHED = "finished"
