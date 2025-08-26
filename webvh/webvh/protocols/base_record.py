"""Module for handling pending webvh dids."""

import logging
from typing import Any, Optional

from acapy_agent.core.profile import Profile
from aries_askar import AskarError
from .states import WitnessingState

LOGGER = logging.getLogger(__name__)


class BasePendingRecord:
    """Base class to manage pending witness requests."""

    RECORD_TYPE = "generic_record"
    RECORD_TOPIC = "generic-record"
    EVENT_NAMESPACE: str = "acapy::record"
    instance = None
    record_ids = None

    def __new__(cls, *args, **kwargs):
        """Create a new instance of the class."""
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    async def _check_and_initialize(self, profile: Profile):
        """Check and initialize the class."""
        if self.record_ids is None:
            async with profile.session() as session:
                pending_records = await session.handle.fetch(
                    self.RECORD_TYPE, self.RECORD_TYPE
                )
                if not pending_records:
                    self.record_ids = set()
                    await session.handle.insert(
                        self.RECORD_TYPE,
                        self.RECORD_TYPE,
                        value_json=list(self.record_ids),
                    )
                else:
                    self.record_ids = set(pending_records.value_json)

    async def _save_pending_record_ids(self, profile: Profile):
        async with profile.session() as session:
            # This is used to force save with newest when there is a race condition
            try:
                await session.handle.remove(self.RECORD_TYPE, self.RECORD_TYPE)
            except AskarError:
                pass
            await session.handle.insert(
                self.RECORD_TYPE, self.RECORD_TYPE, value_json=list(self.record_ids)
            )

    async def set_pending_record_id(self, profile: Profile, record_id: str):
        """Set a new witnessing requests."""
        await self._check_and_initialize(profile)
        self.record_ids.add(record_id)
        await self._save_pending_record_ids(profile)

    async def remove_pending_record_id(self, profile: Profile, record_id: str):
        """Remove a pending record_id witnessing requests."""
        await self._check_and_initialize(profile)
        self.record_ids.discard(record_id)
        await self._save_pending_record_ids(profile)

    async def get_pending_record_ids(self, profile: Profile) -> set:
        """Get all pending record_ids."""
        await self._check_and_initialize(profile)
        return self.record_ids

    async def get_pending_records(self, profile: Profile) -> set:
        """Get all pending records."""
        async with profile.session() as session:
            entries = await session.handle.fetch_all(self.RECORD_TYPE)
        return [entry.value_json for entry in entries]

    async def get_pending_record(self, profile: Profile, record_id: str) -> set:
        """Get a pending record given a record_id."""
        async with profile.session() as session:
            entry = await session.handle.fetch(self.RECORD_TYPE, record_id)
        return entry.value_json, entry.tags.get("connection_id")

    async def remove_pending_record(self, profile: Profile, record_id: str) -> set:
        """Remove a pending record given a record_id."""
        async with profile.session() as session:
            await session.handle.remove(self.RECORD_TYPE, record_id)

        return {"status": "success", "message": f"Removed {self.RECORD_TYPE}."}

    async def save_pending_record(
        self,
        profile: Profile,
        scid: str,
        record: dict,
        record_id: str,
        connection_id: str = "",
    ) -> set:
        """Save a pending record given a scid."""
        pending_record = {
            "record_id": record_id,
            "record_type": self.RECORD_TYPE,
            "record": record,
            "state": WitnessingState.PENDING.value,
            "scid": scid,
        }
        async with profile.session() as session:
            await session.handle.insert(
                self.RECORD_TYPE,
                record_id,
                value_json=pending_record,
                tags={"connection_id": connection_id},
            )
        await self.emit_event(profile, pending_record)

    async def emit_event(self, profile: Profile, payload: Optional[Any] = None):
        """Emit an event.

        Args:
            profile: The profile to use
            payload: The event payload
        """

        if not self.RECORD_TYPE:
            return

        topic = f"{self.EVENT_NAMESPACE}::{self.RECORD_TYPE}"

        if not payload:
            payload = self.serialize()

        async with profile.session() as session:
            await session.emit_event(topic, payload, True)
