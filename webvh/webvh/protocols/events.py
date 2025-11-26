"""Witness Event Manager for handling witness-related events."""

import logging
from typing import Optional

from acapy_agent.core.event_bus import Event, EventBus
from acapy_agent.core.profile import Profile
from acapy_agent.resolver.did_resolver import DIDResolver

from .states import WitnessingState

LOGGER = logging.getLogger(__name__)

WITNESS_EVENT_PREFIX = "witness_response::"


class WitnessEventManager:
    """Manages witness-related event firing and handling."""

    def __init__(self, profile: Profile):
        """Initialize the WitnessEventManager with a profile."""
        self.profile = profile

    def _get_event_bus(self) -> EventBus:
        """Get the event bus from the profile."""
        return self.profile.inject(EventBus)

    def _build_event_name(self, record_id: str) -> str:
        """Build the event name for a given record ID."""
        return f"{WITNESS_EVENT_PREFIX}{record_id}"

    async def fire_pending_event(
        self, record_id: str, document: dict, document_type: str = "log_entry"
    ):
        """Fire a pending witness event.

        Args:
            record_id: The unique identifier for this witness request
            document: The document (log entry or attested resource) awaiting witness
            document_type: Type of document ("log_entry" or "attested_resource")
        """
        event_bus = self._get_event_bus()
        await event_bus.notify(
            self.profile,
            Event(
                self._build_event_name(record_id),
                {
                    "document": document,
                    "metadata": {
                        "state": WitnessingState.PENDING.value,
                        "document_type": document_type,
                    },
                },
            ),
        )
        LOGGER.debug(
            "Fired pending witness event for record_id=%s, document_type=%s",
            record_id,
            document_type,
        )

    async def fire_attested_event(
        self,
        record_id: str,
        document: dict,
        witness_signature: Optional[dict] = None,
        document_type: str = "log_entry",
    ):
        """Fire an attested witness event.

        Args:
            record_id: The unique identifier for this witness request
            document: The document (log entry or attested resource) that was attested
            witness_signature: Optional witness signature/proof
            document_type: Type of document ("log_entry" or "attested_resource")
        """
        event_bus = self._get_event_bus()
        await event_bus.notify(
            self.profile,
            Event(
                self._build_event_name(record_id),
                {
                    "document": document,
                    "witness_signature": witness_signature,
                    "metadata": {
                        "state": WitnessingState.ATTESTED.value,
                        "document_type": document_type,
                    },
                },
            ),
        )
        LOGGER.debug(
            "Fired attested witness event for record_id=%s, document_type=%s",
            record_id,
            document_type,
        )

    async def fire_post_attested_event(self, record_id: str, did: str):
        """Fire a post-attested event after resolving the DID document.

        This event is fired after a DID operation has been completed and the
        DID document has been resolved from the server.

        Args:
            record_id: The unique identifier for this witness request
            did: The DID that was resolved
        """
        async with self.profile.session() as session:
            resolver = session.inject(DIDResolver)
            resolved_did_doc = (
                await resolver.resolve_with_metadata(self.profile, did)
            ).serialize()

        event_bus = self._get_event_bus()
        metadata = resolved_did_doc["metadata"]
        metadata["state"] = WitnessingState.ATTESTED.value

        await event_bus.notify(
            self.profile,
            Event(
                self._build_event_name(record_id),
                {
                    "document": resolved_did_doc["did_document"],
                    "metadata": metadata,
                },
            ),
        )
        LOGGER.debug(
            "Fired post-attested witness event for record_id=%s, did=%s",
            record_id,
            did,
        )

    def get_event_pattern(self, record_id: str) -> str:
        """Get the event pattern for waiting on a specific record ID.

        Args:
            record_id: The unique identifier for the witness request

        Returns:
            A regex pattern string for matching the event
        """
        return rf"^{WITNESS_EVENT_PREFIX}{record_id}$"


