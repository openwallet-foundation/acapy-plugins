"""Module for handling pending webvh dids."""

from ..base_record import BasePendingRecord


class PendingAttestedResourceRecord(BasePendingRecord):
    """Class to manage pending webvh log entry witness requests."""

    RECORD_TYPE = "pending_attested_resource"
    instance = None
    scids = None
