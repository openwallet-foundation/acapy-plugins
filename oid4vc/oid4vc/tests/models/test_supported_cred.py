import pytest
from acapy_agent.core.profile import Profile

from oid4vc.models.supported_cred import SupportedCredential


@pytest.fixture
def record():
    yield SupportedCredential(
        format="jwt_vc_json",
        identifier="MyCredential",
        cryptographic_suites_supported=["EdDSA"],
        proof_types_supported={"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
        format_data={
            "credentialSubject": {"name": "alice"},
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
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
        if record.supported_cred_id is None:
            pytest.fail("No supported_cred_id after save")
        loaded = await SupportedCredential.retrieve_by_id(
            session, record.supported_cred_id
        )
        assert loaded == record


def test_to_issuer_metadata(record: SupportedCredential):
    assert record.to_issuer_metadata() == {
        "format": "jwt_vc_json",
        "id": "MyCredential",
        "credential_signing_alg_values_supported": ["EdDSA"],
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
        },
        "credential_definition": {
            "credentialSubject": {"name": "alice"},
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        },
    }
