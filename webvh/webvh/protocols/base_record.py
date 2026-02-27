"""Module for handling pending webvh dids."""

import logging
from typing import Any, List, Optional

from aries_askar import AskarError, AskarErrorCode
from acapy_agent.core.profile import Profile
from .states import WitnessingState

LOGGER = logging.getLogger(__name__)

INDEX_RECORD_ID = "_index"


class BasePendingRecord:
    """Base class to manage pending witness requests."""

    RECORD_TYPE = "generic_record"
    RECORD_TOPIC = "generic-record"
    EVENT_NAMESPACE: str = "acapy::record"
    instance = None

    def __new__(cls, *args, **kwargs):
        """Create a new instance of the class."""
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    async def _get_index(self, profile: Profile) -> List[str]:
        """Get the list of pending record IDs from the index."""
        async with profile.session() as session:
            try:
                entry = await session.handle.fetch(self.RECORD_TYPE, INDEX_RECORD_ID)
                ids = entry.value_json if entry else []
                return ids if isinstance(ids, list) else []
            except Exception:
                return []

    async def _save_index(self, profile: Profile, record_ids: List[str]) -> None:
        """Save the index of pending record IDs."""
        async with profile.session() as session:
            try:
                await session.handle.replace(
                    self.RECORD_TYPE,
                    INDEX_RECORD_ID,
                    value_json=record_ids,
                    tags={},
                )
            except AskarError as err:
                if err.code != AskarErrorCode.NOT_FOUND:
                    raise
                await session.handle.insert(
                    self.RECORD_TYPE,
                    INDEX_RECORD_ID,
                    value_json=record_ids,
                    tags={},
                )

    async def get_pending_records(self, profile: Profile) -> list:
        """Get all pending records by fetching each from the index."""
        record_ids = await self._get_index(profile)
        results = []
        async with profile.session() as session:
            for record_id in record_ids:
                if record_id == INDEX_RECORD_ID:
                    continue
                try:
                    entry = await session.handle.fetch(self.RECORD_TYPE, record_id)
                    if entry and isinstance(entry.value_json, dict):
                        results.append(entry.value_json)
                except Exception:
                    pass
        if not results and not record_ids:
            # Fallback: index may be empty (e.g., migration), try fetch_all
            try:
                async with profile.session() as session:
                    entries = await session.handle.fetch_all(self.RECORD_TYPE)
                results = [
                    e.value_json
                    for e in (list(entries) if entries else [])
                    if isinstance(e.value_json, dict)
                ]
            except Exception:
                pass
        return results

    async def get_pending_record(self, profile: Profile, record_id: str) -> set:
        """Get a pending record given a record_id.

        Returns (record_dict, connection_id). If no record is found, returns (None, None).
        """
        async with profile.session() as session:
            entry = await session.handle.fetch(self.RECORD_TYPE, record_id)
        if entry is None:
            return None, None
        tags = entry.tags or {}
        return entry.value_json, tags.get("connection_id")

    async def remove_pending_record(self, profile: Profile, record_id: str) -> set:
        """Remove a pending record given a record_id.

        If the record does not exist (e.g. already removed or different wallet),
        treats as success (idempotent).
        """
        async with profile.session() as session:
            try:
                await session.handle.remove(self.RECORD_TYPE, record_id)
            except Exception as e:
                if "not found" in str(e).lower() or "Entry not found" in str(e):
                    pass  # idempotent: already gone
                else:
                    raise
        record_ids = await self._get_index(profile)
        if record_id in record_ids:
            record_ids.remove(record_id)
            await self._save_index(profile, record_ids)
        return {"status": "success", "message": f"Removed {self.RECORD_TYPE}."}

    async def save_pending_record(
        self,
        profile: Profile,
        scid: str,
        record: dict,
        record_id: str,
        connection_id: str = "",
        role: str = None,
    ) -> set:
        """Save a pending record given a scid.

        Args:
            profile: The profile to use
            scid: The short circuit identifier
            record: The record document to save
            record_id: The unique record identifier
            connection_id: The connection ID (empty for self-witnessing)
            role: The role of the agent saving ("controller", "witness", "self-witness")
        """
        role_value = role or "controller"  # Default for backwards compatibility
        pending_record = {
            "record_id": record_id,
            "record_type": self.RECORD_TYPE,
            "record": record,
            "state": WitnessingState.PENDING.value,
            "scid": scid,
            "role": role_value,
        }
        async with profile.session() as session:
            try:
                await session.handle.insert(
                    self.RECORD_TYPE,
                    record_id,
                    value_json=pending_record,
                    tags={"connection_id": connection_id or "", "role": role_value},
                )
            except AskarError as err:
                if err.code != AskarErrorCode.DUPLICATE:
                    raise
                # Record may already exist (e.g., witness saved first in shared storage)
                await session.handle.replace(
                    self.RECORD_TYPE,
                    record_id,
                    value_json=pending_record,
                    tags={"connection_id": connection_id or "", "role": role_value},
                )
        record_ids = await self._get_index(profile)
        if record_id not in record_ids:
            record_ids.append(record_id)
            await self._save_index(profile, record_ids)
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
