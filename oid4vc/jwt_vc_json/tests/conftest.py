from unittest.mock import MagicMock

import pytest
from acapy_agent.admin.request_context import AdminRequestContext

from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.public_routes import PopResult

_EXCHANGE_ID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def body():
    items = {"format": "jwt_vc_json", "types": ["OntarioTestPhotoCard"], "proof": {}}
    mock = MagicMock()
    mock.__getitem__ = lambda _, k: items[k]
    yield mock


@pytest.fixture
def supported():
    yield SupportedCredential(
        format_data={"types": ["VerifiableCredential", "PhotoCard"]},
        vc_additional_data={
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://issuer-controller1.stg.ngrok.io/url/schema/photo-card.jsonld",
            ],
            "type": ["VerifiableCredential", "PhotoCard"],
        },
    )


@pytest.fixture
def ex_record():
    yield OID4VCIExchangeRecord(
        exchange_id=_EXCHANGE_ID,
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


@pytest.fixture
def pop():
    yield PopResult(
        headers=None,
        payload=None,
        verified=True,
        holder_kid="did:key:example-kid#0",
        holder_jwk=None,
    )


@pytest.fixture
async def context():
    """Test AdminRequestContext."""
    from acapy_agent.utils.testing import create_test_profile

    profile = await create_test_profile()
    yield AdminRequestContext(profile)
