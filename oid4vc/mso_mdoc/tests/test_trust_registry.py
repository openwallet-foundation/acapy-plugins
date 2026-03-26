"""Unit tests for TrustAnchorRecord and MdocSigningKeyRecord.

Also covers the processor-layer functions that use these records:
- ``_get_trust_anchors()`` — queries TrustAnchorRecord with doctype-aware filtering.
- ``_resolve_signing_key()`` — resolves signing key from registry or legacy fallback.
- ``_assign_status_entry()`` — assigns IETF Token Status List entry at issuance.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.utils.testing import create_test_profile

from ..trust_anchor import TrustAnchorRecord, TrustAnchorRecordSchema
from ..signing_key import MdocSigningKeyRecord, MdocSigningKeyRecordSchema
from ..cred_processor import _get_trust_anchors, MsoMdocCredProcessor


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
async def profile():
    """In-memory test profile."""
    profile = await create_test_profile({"admin.admin_insecure_mode": True})
    yield profile


@pytest.fixture(scope="module")
def context(profile):
    """AdminRequestContext backed by the test profile."""
    yield AdminRequestContext(profile)


# ---------------------------------------------------------------------------
# TrustAnchorRecord tests
# ---------------------------------------------------------------------------


class TestTrustAnchorRecord:
    """Tests for TrustAnchorRecord model."""

    def test_defaults(self):
        """Record initialises with sensible defaults."""
        rec = TrustAnchorRecord(certificate_pem="CERT")
        assert rec.purpose == "iaca"
        assert rec.doctype is None
        assert rec.label is None
        assert rec.certificate_pem == "CERT"

    def test_record_value_contains_all_fields(self):
        """record_value exposes all stored fields."""
        rec = TrustAnchorRecord(
            doctype="org.iso.18013.5.1.mDL",
            purpose="reader_auth",
            label="My CA",
            certificate_pem="PEM",
        )
        rv = rec.record_value
        assert rv["doctype"] == "org.iso.18013.5.1.mDL"
        assert rv["purpose"] == "reader_auth"
        assert rv["label"] == "My CA"
        assert rv["certificate_pem"] == "PEM"

    def test_tag_names(self):
        """TAG_NAMES contains doctype and purpose for filtered queries."""
        assert "doctype" in TrustAnchorRecord.TAG_NAMES
        assert "purpose" in TrustAnchorRecord.TAG_NAMES

    def test_serialise_round_trip(self):
        """Schema serialisation / deserialisation preserves data."""
        rec = TrustAnchorRecord(
            doctype="org.iso.18013.5.1.mDL",
            purpose="iaca",
            label="Root CA",
            certificate_pem="-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n",
        )
        schema = TrustAnchorRecordSchema()
        serialised = schema.dump(rec)
        assert serialised["certificate_pem"].startswith("-----BEGIN")
        assert serialised["purpose"] == "iaca"
        assert serialised["doctype"] == "org.iso.18013.5.1.mDL"

    @pytest.mark.asyncio
    async def test_save_and_retrieve(self, profile):
        """Save and retrieve a record via the profile session."""
        rec = TrustAnchorRecord(
            doctype="org.iso.18013.5.1.mDL",
            purpose="iaca",
            label="Save Retrieve Test",
            certificate_pem="CERT_CONTENT",
        )
        async with profile.session() as session:
            await rec.save(session, reason="unit test")
            retrieved = await TrustAnchorRecord.retrieve_by_id(session, rec.id)

        assert retrieved.certificate_pem == "CERT_CONTENT"
        assert retrieved.label == "Save Retrieve Test"
        assert retrieved.doctype == "org.iso.18013.5.1.mDL"

    @pytest.mark.asyncio
    async def test_query_by_purpose(self, profile):
        """Query by purpose tag returns correct records."""
        iaca = TrustAnchorRecord(purpose="iaca", certificate_pem="IACA_CERT")
        reader = TrustAnchorRecord(purpose="reader_auth", certificate_pem="READER_CERT")

        async with profile.session() as session:
            await iaca.save(session, reason="query test")
            await reader.save(session, reason="query test")

            iaca_records = await TrustAnchorRecord.query(
                session, tag_filter={"purpose": "iaca"}
            )
            reader_records = await TrustAnchorRecord.query(
                session, tag_filter={"purpose": "reader_auth"}
            )

        iaca_ids = {r.id for r in iaca_records}
        reader_ids = {r.id for r in reader_records}
        assert iaca.id in iaca_ids
        assert reader.id in reader_ids
        assert reader.id not in iaca_ids

    @pytest.mark.asyncio
    async def test_delete(self, profile):
        """Delete removes the record."""
        rec = TrustAnchorRecord(certificate_pem="TO_DELETE")
        from acapy_agent.storage.error import StorageNotFoundError

        async with profile.session() as session:
            await rec.save(session, reason="delete test")
            await rec.delete_record(session)

            with pytest.raises(StorageNotFoundError):
                await TrustAnchorRecord.retrieve_by_id(session, rec.id)


# ---------------------------------------------------------------------------
# MdocSigningKeyRecord tests
# ---------------------------------------------------------------------------


class TestMdocSigningKeyRecord:
    """Tests for MdocSigningKeyRecord model."""

    def test_record_value_includes_private_key(self):
        """record_value persists private_key_pem (even though API hides it)."""
        rec = MdocSigningKeyRecord(
            doctype="org.iso.18013.5.1.mDL",
            label="DS Key",
            private_key_pem="PRIV_KEY",
            certificate_pem="CERT",
        )
        rv = rec.record_value
        assert rv["private_key_pem"] == "PRIV_KEY"
        assert rv["certificate_pem"] == "CERT"

    def test_schema_private_key_is_load_only(self):
        """private_key_pem must not be in the schema dump output."""
        rec = MdocSigningKeyRecord(
            private_key_pem="SECRET",
            certificate_pem="CERT",
        )
        schema = MdocSigningKeyRecordSchema()
        dumped = schema.dump(rec)
        assert "private_key_pem" not in dumped, (
            "private_key_pem must be load_only and not serialised in GET responses"
        )

    def test_tag_names(self):
        """TAG_NAMES contains doctype and label."""
        assert "doctype" in MdocSigningKeyRecord.TAG_NAMES
        assert "label" in MdocSigningKeyRecord.TAG_NAMES

    @pytest.mark.asyncio
    async def test_save_retrieve_private_key(self, profile):
        """Private key survives a save/retrieve round-trip via the database."""
        rec = MdocSigningKeyRecord(
            doctype="org.iso.18013.5.1.mDL",
            label="DB persist test",
            private_key_pem="SECRET_KEY_PEM",
            certificate_pem="CERT_PEM",
        )
        async with profile.session() as session:
            await rec.save(session, reason="unit test")
            retrieved = await MdocSigningKeyRecord.retrieve_by_id(session, rec.id)

        # Private key is stored in the encrypted DB record and readable in code
        assert retrieved.private_key_pem == "SECRET_KEY_PEM"
        assert retrieved.certificate_pem == "CERT_PEM"

    @pytest.mark.asyncio
    async def test_query_by_doctype(self, profile):
        """Query by doctype tag returns only matching records."""
        mdl_key = MdocSigningKeyRecord(
            doctype="org.iso.18013.5.1.mDL",
            private_key_pem="MDL_KEY",
            certificate_pem="MDL_CERT",
        )
        other_key = MdocSigningKeyRecord(
            doctype="org.example.other",
            private_key_pem="OTHER_KEY",
            certificate_pem="OTHER_CERT",
        )
        async with profile.session() as session:
            await mdl_key.save(session, reason="query test")
            await other_key.save(session, reason="query test")

            mdl_records = await MdocSigningKeyRecord.query(
                session, tag_filter={"doctype": "org.iso.18013.5.1.mDL"}
            )
            other_records = await MdocSigningKeyRecord.query(
                session, tag_filter={"doctype": "org.example.other"}
            )

        mdl_ids = {r.id for r in mdl_records}
        other_ids = {r.id for r in other_records}
        assert mdl_key.id in mdl_ids
        assert other_key.id in other_ids
        assert other_key.id not in mdl_ids


# ---------------------------------------------------------------------------
# _get_trust_anchors processor function tests
# ---------------------------------------------------------------------------


class TestGetTrustAnchors:
    """Tests for the _get_trust_anchors() module-level helper."""

    @pytest.mark.asyncio
    async def test_returns_all_iaca_anchors_when_no_doctype(self, profile):
        """Without a doctype filter, all IACA records (any doctype) are returned."""
        wildcard = TrustAnchorRecord(purpose="iaca", certificate_pem="WILDCARD_CERT")
        specific = TrustAnchorRecord(
            purpose="iaca",
            doctype="org.iso.18013.5.1.mDL",
            certificate_pem="MDL_CERT",
        )
        async with profile.session() as session:
            await wildcard.save(session, reason="test")
            await specific.save(session, reason="test")

        anchors = await _get_trust_anchors(profile)

        # Both certificates should be returned (no doctype filtering applied)
        assert "WILDCARD_CERT" in anchors
        assert "MDL_CERT" in anchors

    @pytest.mark.asyncio
    async def test_doctype_filter_includes_wildcard_and_exact(self, profile):
        """With a doctype, records with matching doctype AND wildcards are included."""
        wildcard = TrustAnchorRecord(purpose="iaca", certificate_pem="WILDCARD_W2")
        matching = TrustAnchorRecord(
            purpose="iaca",
            doctype="org.iso.18013.5.1.mDL",
            certificate_pem="MDL_CERT_W2",
        )
        other = TrustAnchorRecord(
            purpose="iaca",
            doctype="org.example.other",
            certificate_pem="OTHER_CERT_W2",
        )
        async with profile.session() as session:
            await wildcard.save(session, reason="test")
            await matching.save(session, reason="test")
            await other.save(session, reason="test")

        anchors = await _get_trust_anchors(profile, doctype="org.iso.18013.5.1.mDL")

        assert "WILDCARD_W2" in anchors
        assert "MDL_CERT_W2" in anchors
        assert "OTHER_CERT_W2" not in anchors

    @pytest.mark.asyncio
    async def test_reader_auth_records_excluded(self, profile):
        """Records with purpose != 'iaca' are never returned."""
        reader = TrustAnchorRecord(
            purpose="reader_auth", certificate_pem="READER_CERT_EXCL"
        )
        async with profile.session() as session:
            await reader.save(session, reason="test")

        anchors = await _get_trust_anchors(profile)
        assert "READER_CERT_EXCL" not in anchors


# ---------------------------------------------------------------------------
# _resolve_signing_key processor method tests
# ---------------------------------------------------------------------------


class TestResolveSigningKey:
    """Tests for MsoMdocCredProcessor._resolve_signing_key()."""

    @pytest.fixture
    def processor(self):
        return MsoMdocCredProcessor()

    @pytest.mark.asyncio
    async def test_resolves_from_signing_key_record_by_doctype(self, processor):
        """When a MdocSigningKeyRecord exists for the doctype, it is used."""
        from oid4vc.models.supported_cred import SupportedCredential

        # Use a fresh isolated profile to avoid test pollution from module-scoped profile
        fresh_profile = await create_test_profile({"admin.admin_insecure_mode": True})

        key_rec = MdocSigningKeyRecord(
            doctype="org.iso.18013.5.1.mDL",
            private_key_pem="PRIV_KEY_FROM_RECORD",
            certificate_pem="CERT_FROM_RECORD",
        )
        async with fresh_profile.session() as session:
            await key_rec.save(session, reason="test")

        supported = SupportedCredential(
            format="mso_mdoc",
            format_data={"doctype": "org.iso.18013.5.1.mDL"},
        )
        result = await processor._resolve_signing_key(supported, fresh_profile)

        assert result["private_key_pem"] == "PRIV_KEY_FROM_RECORD"
        assert result["certificate_pem"] == "CERT_FROM_RECORD"


# ---------------------------------------------------------------------------
# _assign_status_entry processor method tests
# ---------------------------------------------------------------------------


class TestAssignStatusEntry:
    """Tests for MsoMdocCredProcessor._assign_status_entry()."""

    @pytest.fixture
    def processor(self):
        return MsoMdocCredProcessor()

    @pytest.mark.asyncio
    async def test_returns_none_when_no_status_list_def_id(self, processor, context):
        """No status_list_def_id in vc_additional_data → returns None."""
        from oid4vc.models.supported_cred import SupportedCredential

        supported = SupportedCredential(format="mso_mdoc", vc_additional_data={})
        result = await processor._assign_status_entry(context, supported, "org.example")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_status_list_plugin_not_installed(
        self, processor, context
    ):
        """When status_list plugin ImportError occurs → returns None gracefully."""
        from oid4vc.models.supported_cred import SupportedCredential

        supported = SupportedCredential(
            format="mso_mdoc",
            vc_additional_data={
                "status_list_def_id": "def-123",
                "status_list_base_uri": "http://issuer/status",
            },
        )

        with patch.dict("sys.modules", {"status_list.status_list.v1_0": None}):
            result = await processor._assign_status_entry(
                context, supported, "org.example"
            )
        # Should fail-gracefully when plugin not available
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_status_claim_when_entry_assigned(self, processor, context):
        """When status handler assigns an entry, returns {status_list: {idx, uri}}."""
        from oid4vc.models.supported_cred import SupportedCredential

        supported = SupportedCredential(
            format="mso_mdoc",
            vc_additional_data={
                "status_list_def_id": "def-456",
                "status_list_base_uri": "http://issuer/status",
            },
        )

        mock_entry = {"list_number": "0", "list_index": 7}
        mock_status_handler = MagicMock()
        mock_status_handler.assign_status_list_entry = AsyncMock(return_value=mock_entry)

        # _assign_status_entry does:
        #   from status_list.status_list.v1_0 import status_handler as _status_handler
        # Python resolves this by looking at
        # sys.modules["status_list.status_list.v1_0"].status_handler
        mock_module = MagicMock(status_handler=mock_status_handler)

        sys_modules_patch = {
            "status_list": MagicMock(),
            "status_list.status_list": MagicMock(),
            "status_list.status_list.v1_0": mock_module,
            "status_list.status_list.v1_0.status_handler": mock_status_handler,
        }
        with patch.dict("sys.modules", sys_modules_patch):
            result = await processor._assign_status_entry(
                context, supported, "org.example"
            )

        assert result is not None
        assert result["status_list"]["idx"] == 7
        assert result["status_list"]["uri"] == "http://issuer/status/0"
