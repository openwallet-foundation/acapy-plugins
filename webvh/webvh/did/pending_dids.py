"""Module for handling pending webvh dids."""

from acapy_agent.core.profile import Profile
from aries_askar import AskarError

RECORD_TYPE = "pending_webvh_dids"


class PendingWebvhDids:
    """Class to manage pending webvh dids."""

    instance = None
    dids = None

    def __new__(cls, *args, **kwargs):
        """Create a new instance of the class."""
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    async def _check_and_initialize(self, profile: Profile):
        """Check and initialize the class."""
        if self.dids is None:
            async with profile.session() as session:
                pending_dids_record = await session.handle.fetch(RECORD_TYPE, RECORD_TYPE)
                if not pending_dids_record:
                    self.dids = set()
                    await session.handle.insert(
                        RECORD_TYPE, RECORD_TYPE, value_json=list(self.dids)
                    )
                else:
                    self.dids = set(pending_dids_record.value_json)

    async def _save_pending_dids(self, profile: Profile):
        async with profile.session() as session:
            # This is used to force save with newest when there is a race condition
            try:
                await session.handle.remove(RECORD_TYPE, RECORD_TYPE)
            except AskarError:
                pass
            await session.handle.insert(
                RECORD_TYPE, RECORD_TYPE, value_json=list(self.dids)
            )

    async def set_pending_did(self, profile: Profile, did: str):
        """Set a pending did."""
        await self._check_and_initialize(profile)
        self.dids.add(did)
        await self._save_pending_dids(profile)

    async def remove_pending_did(self, profile: Profile, did: str):
        """Remove a pending did."""
        await self._check_and_initialize(profile)
        self.dids.discard(did)
        await self._save_pending_dids(profile)

    async def get_pending_dids(self, profile: Profile) -> set:
        """Get all pending dids."""
        await self._check_and_initialize(profile)
        return self.dids
