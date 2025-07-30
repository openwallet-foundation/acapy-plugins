"""Module for handling pending webvh dids."""

import logging

from acapy_agent.core.profile import Profile
from aries_askar import AskarError

LOGGER = logging.getLogger(__name__)


class BasePendingRecord:
    """Base class to manage pending witness requests."""

    RECORD_TYPE = "generic_record"
    instance = None
    scids = None

    def __new__(cls, *args, **kwargs):
        """Create a new instance of the class."""
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    async def _check_and_initialize(self, profile: Profile):
        """Check and initialize the class."""
        if self.scids is None:
            async with profile.session() as session:
                pending_scids_record = await session.handle.fetch(
                    self.RECORD_TYPE, self.RECORD_TYPE
                )
                if not pending_scids_record:
                    self.scids = set()
                    await session.handle.insert(
                        self.RECORD_TYPE, self.RECORD_TYPE, value_json=list(self.scids)
                    )
                else:
                    self.scids = set(pending_scids_record.value_json)

    async def _save_pending_scids(self, profile: Profile):
        async with profile.session() as session:
            # This is used to force save with newest when there is a race condition
            try:
                await session.handle.remove(self.RECORD_TYPE, self.RECORD_TYPE)
            except AskarError:
                pass
            await session.handle.insert(
                self.RECORD_TYPE, self.RECORD_TYPE, value_json=list(self.scids)
            )

    async def set_pending_scid(self, profile: Profile, scid: str):
        """Set a new witnessing requests."""
        await self._check_and_initialize(profile)
        self.scids.add(scid)
        await self._save_pending_scids(profile)

    async def remove_pending_scid(self, profile: Profile, scid: str):
        """Remove a pending scid witnessing requests."""
        await self._check_and_initialize(profile)
        self.scids.discard(scid)
        await self._save_pending_scids(profile)

    async def get_pending_scids(self, profile: Profile) -> set:
        """Get all pending scids."""
        await self._check_and_initialize(profile)
        return self.scids

    async def get_pending_records(self, profile: Profile) -> set:
        """Get all pending records."""
        async with profile.session() as session:
            entries = await session.handle.fetch_all(self.RECORD_TYPE)
        return [entry.value_json for entry in entries]

    async def get_pending_record(self, profile: Profile, scid: str) -> set:
        """Get a pending record given a scid."""
        async with profile.session() as session:
            entry = await session.handle.fetch(self.RECORD_TYPE, scid)
        return entry.value_json, entry.tags.get("connection_id")

    async def remove_pending_record(self, profile: Profile, scid: str) -> set:
        """Remove a pending record given a scid."""
        async with profile.session() as session:
            await session.handle.remove(self.RECORD_TYPE, scid)

        return {"status": "success", "message": f"Removed {self.RECORD_TYPE}."}

    async def save_pending_record(
        self, profile: Profile, scid: str, record: dict, connection_id: str = ""
    ) -> set:
        """Save a pending record given a scid."""
        async with profile.session() as session:
            await session.handle.insert(
                self.RECORD_TYPE,
                scid,
                value_json=record,
                tags={"connection_id": connection_id},
            )
