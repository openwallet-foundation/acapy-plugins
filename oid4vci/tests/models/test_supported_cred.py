from aries_cloudagent.core.profile import Profile
import pytest

from oid4vci.v1_0.models.supported_cred import SupportedCredential


@pytest.fixture
def record():
    yield SupportedCredential(
        format="jwt_vc_json",
        identifier="MyCredential",
        cryptographic_suites_supported=["EdDSA"],
        format_data={
            "credentialSubject": {"name": "alice"},
        },
    )


def test_serde(record: SupportedCredential):
    record._id = "123"
    serialized = record.serialize()
    deserialized = SupportedCredential.deserialize(serialized)
    assert record == deserialized


@pytest.mark.asyncio
async def test_save(profile: Profile, record: SupportedCredential):
    async with profile.session() as session:
        await record.save(session)
        loaded = await SupportedCredential.retrieve_by_id(
            session, record.supported_cred_id
        )
        assert loaded == record
