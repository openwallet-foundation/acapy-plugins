import pytest
from acapy_agent.core.profile import Profile

from oid4vc.models.exchange import OID4VCIExchangeRecord


@pytest.fixture
def record():
    yield OID4VCIExchangeRecord(
        state=OID4VCIExchangeRecord.STATE_OFFER_CREATED,
        verification_method="did:example:123#key-1",
        issuer_id="did:example:123",
        refresh_id="refresh-123",
        notification_id="notif-123",
        supported_cred_id="456",
        credential_subject={"name": "alice"},
        nonce="789",
        pin="000",
        code="111",
        token="222",
    )


def test_serde(record: OID4VCIExchangeRecord):
    serialized = record.serialize()
    deserialized = OID4VCIExchangeRecord.deserialize(serialized)
    assert record == deserialized


@pytest.mark.asyncio
async def test_save(profile: Profile, record: OID4VCIExchangeRecord):
    async with profile.session() as session:
        await record.save(session)
        loaded = await OID4VCIExchangeRecord.retrieve_by_id(session, record.exchange_id)
        assert loaded == record


def test_eq_and_repr(record: OID4VCIExchangeRecord):
    other = OID4VCIExchangeRecord.deserialize(record.serialize())
    assert record == other
    assert repr(record).startswith("<OID4VCIExchangeRecord(")


def test_update_state(record: OID4VCIExchangeRecord):
    old_state = record.state
    record.state = OID4VCIExchangeRecord.STATE_CREATED
    assert record.state != old_state
    assert record.state == OID4VCIExchangeRecord.STATE_CREATED


@pytest.mark.asyncio
async def test_retrieve_by_code(profile: Profile, record: OID4VCIExchangeRecord):
    async with profile.session() as session:
        await record.save(session)
        if not record.code:
            pytest.skip("No code to test retrieval")
        loaded = await OID4VCIExchangeRecord.retrieve_by_code(session, record.code)
        assert loaded == record


@pytest.mark.asyncio
async def test_retrieve_by_refresh_id(profile: Profile, record: OID4VCIExchangeRecord):
    async with profile.session() as session:
        await record.save(session)
        loaded = await OID4VCIExchangeRecord.retrieve_by_refresh_id(
            session, "refresh-123"
        )
        assert loaded == record


@pytest.mark.asyncio
async def test_delete_record(profile: Profile, record: OID4VCIExchangeRecord):
    async with profile.session() as session:
        await record.save(session)
        await record.delete_record(session)
        with pytest.raises(Exception):
            await OID4VCIExchangeRecord.retrieve_by_id(session, record.exchange_id)
