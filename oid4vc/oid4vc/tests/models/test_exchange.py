import pytest
from acapy_agent.core.profile import Profile

from oid4vc.models.exchange import OID4VCIExchangeRecord


@pytest.fixture
def record():
    yield OID4VCIExchangeRecord(
        state=OID4VCIExchangeRecord.STATE_OFFER_CREATED,
        verification_method="did:example:123#key-1",
        issuer_id="did:example:123",
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
