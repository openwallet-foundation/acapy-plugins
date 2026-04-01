"""Database migration for the OID4VC plugin.

On every startup ``run_migrations`` reads the schema version that was last
stored in Askar, compares it to the currently-installed package version, and
runs the appropriate forward *or* backward transformations so that the
database always reflects what the running code expects.

Adding a new migration
----------------------
1. Write a forward transform ``_to_X_Y_Z_<description>(profile) -> int``.
2. Write the matching backward transform ``_from_X_Y_Z_<description>``.
3. Append a ``_Step`` to ``_STEPS`` (keep the list sorted ascending by version).

The version stored in Askar advances (or retreats) one step at a time so a
crash mid-run leaves the database in a known, named state.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from importlib.metadata import version as _pkg_version
from typing import Awaitable, Callable

from acapy_agent.core.profile import Profile
from acapy_agent.storage.base import BaseStorage
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.storage.record import StorageRecord

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VERSION_RECORD_TYPE = "oid4vc:version"
_VERSION_RECORD_ID = "schema-version"

# Baseline sentinel: data created before version tracking was introduced.
# Any DB that has no version record is implicitly at this version.
_UNVERSIONED = (0, 0, 0)

_DCQL_OLD_RECORD_TYPE = "oid4vp"
_DCQL_NEW_RECORD_TYPE = "oid4vp-dcql"


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

_VersionTuple = tuple[int, ...]


def _parse(version_str: str) -> _VersionTuple:
    """Parse a PEP-440 version string into a comparable tuple of ints."""
    # Strip pre/post/dev suffixes by taking only the numeric release segment.
    numeric = version_str.split("+")[0].split("a")[0].split("b")[0].split("rc")[0]
    return tuple(int(x) for x in numeric.split("."))


def _fmt(version_tuple: _VersionTuple) -> str:
    return ".".join(str(x) for x in version_tuple)


async def _get_db_version(storage: BaseStorage) -> _VersionTuple:
    """Return the schema version currently stored in Askar.

    Returns ``_UNVERSIONED`` when no version record exists (i.e. the database
    was created before this migration system was introduced).
    """
    try:
        record = await storage.get_record(_VERSION_RECORD_TYPE, _VERSION_RECORD_ID)
        return _parse(record.value)
    except StorageNotFoundError:
        return _UNVERSIONED


async def _set_db_version(storage: BaseStorage, ver: _VersionTuple) -> None:
    """Persist the DB schema version to Askar."""
    ver_str = _fmt(ver)
    try:
        record = await storage.get_record(_VERSION_RECORD_TYPE, _VERSION_RECORD_ID)
        await storage.update_record(record, ver_str, {})
    except StorageNotFoundError:
        await storage.add_record(
            StorageRecord(
                type=_VERSION_RECORD_TYPE,
                value=ver_str,
                id=_VERSION_RECORD_ID,
            )
        )


# ---------------------------------------------------------------------------
# Transformations — 0.1.0
# ---------------------------------------------------------------------------


async def _to_0_1_0_dcql_record_type(profile: Profile) -> int:
    """Forward: DCQLQuery RECORD_TYPE "oid4vp" → "oid4vp-dcql".

    All three OID4VP model types shared ``RECORD_TYPE = "oid4vp"`` before
    this change.  DCQLQuery records are identified by a top-level
    ``"credentials"`` key that Presentation and Request bodies never have.
    """
    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        records = await storage.find_all_records(_DCQL_OLD_RECORD_TYPE)

        migrated = 0
        for record in records:
            try:
                body = json.loads(record.value)
            except (json.JSONDecodeError, TypeError):
                LOGGER.warning("Skipping oid4vp record %s: not valid JSON.", record.id)
                continue

            if "credentials" not in body:
                continue  # Presentation / Request — leave untouched

            await storage.delete_record(record)
            await storage.add_record(
                StorageRecord(
                    type=_DCQL_NEW_RECORD_TYPE,
                    value=record.value,
                    tags=record.tags,
                    id=record.id,
                )
            )
            migrated += 1
            LOGGER.info(
                "DCQLQuery %s: type %r → %r",
                record.id,
                _DCQL_OLD_RECORD_TYPE,
                _DCQL_NEW_RECORD_TYPE,
            )

        return migrated


async def _from_0_1_0_dcql_record_type(profile: Profile) -> int:
    """Backward: DCQLQuery RECORD_TYPE "oid4vp-dcql" → "oid4vp".

    Reverses ``_to_0_1_0_dcql_record_type`` so an older version of the code
    that expects all OID4VP records under ``"oid4vp"`` works correctly.
    """
    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        records = await storage.find_all_records(_DCQL_NEW_RECORD_TYPE)

        migrated = 0
        for record in records:
            await storage.delete_record(record)
            await storage.add_record(
                StorageRecord(
                    type=_DCQL_OLD_RECORD_TYPE,
                    value=record.value,
                    tags=record.tags,
                    id=record.id,
                )
            )
            migrated += 1
            LOGGER.info(
                "DCQLQuery %s: type %r → %r",
                record.id,
                _DCQL_NEW_RECORD_TYPE,
                _DCQL_OLD_RECORD_TYPE,
            )

        return migrated


# ---------------------------------------------------------------------------
# Migration registry
# ---------------------------------------------------------------------------

_MigrateFn = Callable[[Profile], Awaitable[int]]


@dataclass
class _Step:
    """One schema-breaking version boundary.

    ``forward`` transforms the DB from the *previous* version's schema to
    this version's schema.  ``backward`` does the reverse.  Both lists are
    applied in order when traversing in their respective direction.
    """

    version: _VersionTuple
    forward: list[_MigrateFn] = field(default_factory=list)
    backward: list[_MigrateFn] = field(default_factory=list)


# Keep sorted ascending by version.
_STEPS: list[_Step] = [
    _Step(
        version=(0, 1, 0),
        forward=[
            _to_0_1_0_dcql_record_type,
        ],
        backward=[
            _from_0_1_0_dcql_record_type,
        ],
    ),
]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def run_migrations(profile: Profile) -> None:
    """Transform the database schema to match the installed package version.

    * **Upgrade**: runs forward transforms for every step between the stored
      version and the current package version.
    * **Downgrade**: runs backward transforms for every step between the
      stored version and the (lower) current package version.
    * **No-op**: stored version equals current package version.

    The stored version is updated after each step so a crash mid-run leaves
    the database in a known, named intermediate state.
    """
    current = _parse(_pkg_version("oid4vc"))

    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        stored = await _get_db_version(storage)

    if stored == current:
        LOGGER.debug("DB already at %s; no migrations needed.", _fmt(current))
        return

    if stored < current:
        steps = [s for s in _STEPS if stored < s.version <= current]
        LOGGER.info(
            "Migrating DB %s → %s (%d step(s)).",
            _fmt(stored),
            _fmt(current),
            len(steps),
        )
        for step in steps:
            LOGGER.info("Applying step %s …", _fmt(step.version))
            for fn in step.forward:
                count = await fn(profile)
                LOGGER.info("  %s: %d record(s) transformed.", fn.__name__, count)
            async with profile.session() as session:
                storage = session.inject(BaseStorage)
                await _set_db_version(storage, step.version)
            LOGGER.info("Step %s complete.", _fmt(step.version))

    else:
        steps = [s for s in reversed(_STEPS) if current < s.version <= stored]
        LOGGER.info(
            "Rolling back DB %s → %s (%d step(s)).",
            _fmt(stored),
            _fmt(current),
            len(steps),
        )
        for step in steps:
            LOGGER.info("Reversing step %s …", _fmt(step.version))
            for fn in step.backward:
                count = await fn(profile)
                LOGGER.info("  %s: %d record(s) transformed.", fn.__name__, count)
            # After reversing this step the DB is at the *previous* version.
            idx = _STEPS.index(step)
            prev = _STEPS[idx - 1].version if idx > 0 else _UNVERSIONED
            async with profile.session() as session:
                storage = session.inject(BaseStorage)
                await _set_db_version(storage, prev)
            LOGGER.info("Step %s reversed; DB now at %s.", _fmt(step.version), _fmt(prev))
