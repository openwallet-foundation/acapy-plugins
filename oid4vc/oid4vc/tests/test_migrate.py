"""Tests for oid4vc/migrate.py."""

from __future__ import annotations

import json

import pytest
from acapy_agent.storage.base import BaseStorage
from acapy_agent.storage.record import StorageRecord
from acapy_agent.utils.testing import create_test_profile
from unittest.mock import patch

from oid4vc.migrate import (
    _DCQL_NEW_RECORD_TYPE,
    _DCQL_OLD_RECORD_TYPE,
    _UNVERSIONED,
    _VERSION_RECORD_TYPE,
    _fmt,
    _from_0_1_0_dcql_record_type,
    _get_db_version,
    _parse,
    _set_db_version,
    _to_0_1_0_dcql_record_type,
    run_migrations,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
async def profile():
    yield await create_test_profile()


def _dcql_record_old(dcql_id: str) -> StorageRecord:
    """Pre-0.1.0 DCQLQuery record: stored under type "oid4vp"."""
    body = {"credentials": [{"id": "cred1", "format": "mso_mdoc"}]}
    return StorageRecord(
        type=_DCQL_OLD_RECORD_TYPE,
        value=json.dumps(body),
        tags={"dcql_query_id": dcql_id},
        id=dcql_id,
    )


def _dcql_record_new(dcql_id: str) -> StorageRecord:
    """Post-0.1.0 DCQLQuery record: stored under type "oid4vp-dcql"."""
    body = {"credentials": [{"id": "cred1", "format": "mso_mdoc"}]}
    return StorageRecord(
        type=_DCQL_NEW_RECORD_TYPE,
        value=json.dumps(body),
        tags={"dcql_query_id": dcql_id},
        id=dcql_id,
    )


def _presentation_record(pres_id: str) -> StorageRecord:
    """OID4VPPresentation/Request record — no 'credentials' key, stays under "oid4vp"."""
    body = {"vp_formats": {}, "state": "request-created"}
    return StorageRecord(
        type=_DCQL_OLD_RECORD_TYPE,
        value=json.dumps(body),
        tags={"state": "request-created"},
        id=pres_id,
    )


async def _store_db_version(profile, version_str: str) -> None:
    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        await _set_db_version(storage, _parse(version_str))


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------


class TestVersionHelpers:
    def test_parse_and_fmt_roundtrip(self):
        assert _fmt(_parse("1.2.3")) == "1.2.3"
        assert _parse("0.0.0") == (0, 0, 0)
        assert _parse("0.1.0") == (0, 1, 0)

    def test_unversioned_is_zero(self):
        assert _UNVERSIONED == (0, 0, 0)

    async def test_get_db_version_returns_unversioned_when_no_record(self, profile):
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            assert await _get_db_version(storage) == _UNVERSIONED

    async def test_set_and_get_db_version(self, profile):
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await _set_db_version(storage, (0, 1, 0))
            assert await _get_db_version(storage) == (0, 1, 0)

    async def test_set_db_version_updates_in_place(self, profile):
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await _set_db_version(storage, (0, 1, 0))
            await _set_db_version(storage, (0, 2, 0))
            assert await _get_db_version(storage) == (0, 2, 0)
            # Only one version record should exist.
            records = await storage.find_all_records(_VERSION_RECORD_TYPE)
            assert len(records) == 1


# ---------------------------------------------------------------------------
# Forward: to 0.1.0 — DCQLQuery type "oid4vp" → "oid4vp-dcql"
# ---------------------------------------------------------------------------


class TestTo010DCQLRecordType:
    async def test_dcql_record_migrated(self, profile):
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await storage.add_record(_dcql_record_old("q1"))

        count = await _to_0_1_0_dcql_record_type(profile)

        assert count == 1
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            new = await storage.find_all_records(_DCQL_NEW_RECORD_TYPE)
            old = await storage.find_all_records(_DCQL_OLD_RECORD_TYPE)
        assert len(new) == 1 and new[0].id == "q1"
        assert len(old) == 0

    async def test_presentation_not_touched(self, profile):
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await storage.add_record(_presentation_record("p1"))

        count = await _to_0_1_0_dcql_record_type(profile)
        assert count == 0
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            remaining = await storage.find_all_records(_DCQL_OLD_RECORD_TYPE)
        assert len(remaining) == 1

    async def test_mixed_records(self, profile):
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await storage.add_record(_dcql_record_old("q1"))
            await storage.add_record(_dcql_record_old("q2"))
            await storage.add_record(_presentation_record("p1"))

        count = await _to_0_1_0_dcql_record_type(profile)
        assert count == 2
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            new = await storage.find_all_records(_DCQL_NEW_RECORD_TYPE)
            old = await storage.find_all_records(_DCQL_OLD_RECORD_TYPE)
        assert {r.id for r in new} == {"q1", "q2"}
        assert len(old) == 1 and old[0].id == "p1"

    async def test_id_and_tags_preserved(self, profile):
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await storage.add_record(_dcql_record_old("q-preserve"))

        await _to_0_1_0_dcql_record_type(profile)
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            (r,) = await storage.find_all_records(_DCQL_NEW_RECORD_TYPE)
        assert r.id == "q-preserve"
        assert r.tags == {"dcql_query_id": "q-preserve"}

    async def test_multiple_calls_idempotent(self, profile):
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await storage.add_record(_dcql_record_old("q1"))

        first = await _to_0_1_0_dcql_record_type(profile)
        second = await _to_0_1_0_dcql_record_type(profile)
        assert first == 1
        assert second == 0  # already under new type, invisible to old-type scan


# ---------------------------------------------------------------------------
# Backward: from 0.1.0 — DCQLQuery type "oid4vp-dcql" → "oid4vp"
# ---------------------------------------------------------------------------


class TestFrom010DCQLRecordType:
    async def test_new_record_rolled_back(self, profile):
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await storage.add_record(_dcql_record_new("q1"))

        count = await _from_0_1_0_dcql_record_type(profile)

        assert count == 1
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            old = await storage.find_all_records(_DCQL_OLD_RECORD_TYPE)
            new = await storage.find_all_records(_DCQL_NEW_RECORD_TYPE)
        assert len(old) == 1 and old[0].id == "q1"
        assert len(new) == 0

    async def test_roundtrip(self, profile):
        """Forward then backward restores original record under old type."""
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            orig = _dcql_record_old("q-rt")
            await storage.add_record(orig)

        await _to_0_1_0_dcql_record_type(profile)
        await _from_0_1_0_dcql_record_type(profile)

        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            old = await storage.find_all_records(_DCQL_OLD_RECORD_TYPE)
            new = await storage.find_all_records(_DCQL_NEW_RECORD_TYPE)
        assert len(old) == 1
        assert old[0].id == "q-rt"
        assert old[0].value == orig.value
        assert len(new) == 0


# ---------------------------------------------------------------------------
# run_migrations — routing and version bookkeeping
# ---------------------------------------------------------------------------


class TestRunMigrations:
    async def test_no_op_when_versions_match(self, profile):
        """If DB version equals package version nothing happens."""
        await _store_db_version(profile, "0.1.0")
        with patch("oid4vc.migrate._pkg_version", return_value="0.1.0"):
            await run_migrations(profile)
        # DB version unchanged
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            assert await _get_db_version(storage) == (0, 1, 0)

    async def test_forward_migration_unversioned_to_0_1_0(self, profile):
        """Unversioned DB (no record) → 0.1.0: forward transforms run."""
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await storage.add_record(_dcql_record_old("q1"))

        with patch("oid4vc.migrate._pkg_version", return_value="0.1.0"):
            await run_migrations(profile)

        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            (dcql,) = await storage.find_all_records(_DCQL_NEW_RECORD_TYPE)
            db_version = await _get_db_version(storage)

        assert "credentials" in json.loads(dcql.value)
        assert db_version == (0, 1, 0)

    async def test_backward_migration_0_1_0_to_unversioned(self, profile):
        """Downgrade: 0.1.0 DB → unversioned package: backward transforms run."""
        await _store_db_version(profile, "0.1.0")
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await storage.add_record(_dcql_record_new("q1"))

        with patch("oid4vc.migrate._pkg_version", return_value="0.0.0"):
            await run_migrations(profile)

        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            (dcql,) = await storage.find_all_records(_DCQL_OLD_RECORD_TYPE)
            new_dcql = await storage.find_all_records(_DCQL_NEW_RECORD_TYPE)
            db_version = await _get_db_version(storage)

        assert "credentials" in json.loads(dcql.value)
        assert len(new_dcql) == 0
        assert db_version == _UNVERSIONED

    async def test_db_version_updated_to_current_after_forward(self, profile):
        with patch("oid4vc.migrate._pkg_version", return_value="0.1.0"):
            await run_migrations(profile)
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            assert await _get_db_version(storage) == (0, 1, 0)

    async def test_db_version_updated_to_current_after_backward(self, profile):
        await _store_db_version(profile, "0.1.0")
        with patch("oid4vc.migrate._pkg_version", return_value="0.0.0"):
            await run_migrations(profile)
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            assert await _get_db_version(storage) == _UNVERSIONED

    async def test_forward_then_backward_roundtrip(self, profile):
        """Upgrade then downgrade leaves DB in original pre-migration shape."""
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await storage.add_record(_dcql_record_old("q1"))
            await storage.add_record(_presentation_record("p1"))

        with patch("oid4vc.migrate._pkg_version", return_value="0.1.0"):
            await run_migrations(profile)

        with patch("oid4vc.migrate._pkg_version", return_value="0.0.0"):
            await run_migrations(profile)

        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            old_oid4vp = await storage.find_all_records(_DCQL_OLD_RECORD_TYPE)
            new_oid4vp = await storage.find_all_records(_DCQL_NEW_RECORD_TYPE)
            db_version = await _get_db_version(storage)

        assert {r.id for r in old_oid4vp} == {"q1", "p1"}
        assert len(new_oid4vp) == 0
        assert db_version == _UNVERSIONED
