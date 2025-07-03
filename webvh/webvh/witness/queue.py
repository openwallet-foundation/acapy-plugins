"""Module for handling pending webvh dids."""

from acapy_agent.core.profile import Profile
from aries_askar import AskarError


class WitnessQueue:
    """Class to manage pending webvh witnessing requests."""

    RECORD_TYPE = "pending_requests"
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

    async def new_request(self, profile: Profile, scid: str):
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
