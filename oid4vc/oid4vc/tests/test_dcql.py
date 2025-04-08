from unittest import mock
import pytest
from acapy_agent.core.profile import Profile
from acapy_agent.tests.mock import CoroutineMock

from oid4vc.cred_processor import CredProcessors, VerifyResult
from oid4vc.dcql import DCQLQueryEvaluator
from oid4vc.models.dcql_query import CredentialQuery, DCQLQuery


raw_query = {
    "credentials": [
        {
            "id": "pid",
            "format": "vc+sd-jwt",
            "meta": {
                "vct_values": ["https://credentials.example.com/identity_credential"]
            },
            "claims": [
                {"path": ["given_name"]},
                {"path": ["family_name"]},
                {"path": ["address", "street_address"]},
            ],
        }
    ]
}


@pytest.mark.asyncio
async def test_dcql_query_deser_roundtrip():
    des_query = DCQLQuery.deserialize(raw_query)
    ser_query = des_query.serialize()

    assert raw_query == ser_query


@pytest.mark.asyncio
async def test_dcql_query_saving(profile: Profile):
    des_query = DCQLQuery.deserialize(raw_query)
    async with profile.session() as session:
        await des_query.save(session=session)

        retrieved_query = await DCQLQuery.retrieve_by_id(session, des_query.dcql_query_id)

    assert len(retrieved_query.credentials) == 1
    assert isinstance(retrieved_query.credentials[0], CredentialQuery)


@pytest.mark.asyncio
async def test_dcql_verify(profile: Profile):
    pres_result_payload = {
        "given_name": "Sally",
        "family_name": "Sparrow",
        "address": {
            "street_address": "123 Main Street",
        },
        "vct": "https://credentials.example.com/identity_credential",
    }
    vp_token = {"pid": "blah"}

    pres_rec = mock.MagicMock()
    mock_cred_processors = mock.MagicMock(CredProcessors)

    mock_pres_verifier = mock.MagicMock()
    mock_pres_verifier.verify_presentation = CoroutineMock(
        return_value=VerifyResult(True, pres_result_payload)
    )
    mock_cred_processors.pres_verifier_for_format = mock.MagicMock(
        return_value=mock_pres_verifier
    )

    mock_cred_verifier = mock.MagicMock()
    mock_cred_verifier.verify_credential = CoroutineMock(
        return_value=VerifyResult(True, pres_result_payload)
    )
    mock_cred_processors.cred_verifier_for_format = mock.MagicMock(
        return_value=mock_cred_verifier
    )

    profile.context.injector.bind_instance(CredProcessors, mock_cred_processors)

    async with profile.session() as session:
        eval = DCQLQueryEvaluator.compile(raw_query)

        verified = await eval.verify(
            profile=profile, vp_token=vp_token, presentation_record=pres_rec
        )

        assert verified.verified
