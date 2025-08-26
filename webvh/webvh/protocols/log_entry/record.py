"""Module for handling pending webvh dids."""

from ..base_record import BasePendingRecord


class PendingLogEntryRecord(BasePendingRecord):
    """Class to manage pending webvh log entry witness requests."""

    RECORD_TYPE = "log-entry"
    RECORD_TOPIC = "log_entry"
    instance = None
    scids = None
