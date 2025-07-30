from unittest import IsolatedAsyncioTestCase

from acapy_agent.messaging.request_context import RequestContext
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile

from ..handlers import WitnessRequestHandler, WitnessResponseHandler
from ..record import PendingAttestedResourceRecord
from ..messages import WitnessRequest, WitnessResponse
from ..routes import (
    get_pending_attested_resources,
    approve_pending_attested_resource,
    reject_pending_attested_resource,
)
from ...states import WitnessingState

record = PendingAttestedResourceRecord()

TEST_SCID = "123"
TEST_RECORD = {
    "id": f"did:webvh:{TEST_SCID}:example.com/resources/123",
    "content": {"schema_name": "Test Schema"},
}


class TestLogEntryProtocol(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile({"wallet.type": "askar-anoncreds"})

    async def test_record(self):
        await record.set_pending_scid(self.profile, TEST_SCID)
        await record.get_pending_scids(self.profile)
        await record.remove_pending_scid(self.profile, TEST_SCID)
        await record.get_pending_scids(self.profile)

        await record.save_pending_record(self.profile, TEST_SCID, TEST_RECORD)
        await record.get_pending_records(self.profile)
        await record.get_pending_record(self.profile, TEST_SCID)
        await record.remove_pending_record(self.profile, TEST_SCID)
        await record.get_pending_records(self.profile)
        await record.get_pending_record(self.profile, TEST_SCID)

    async def test_handler(self):
        context = RequestContext(message=WitnessRequest(document=TEST_RECORD))
        responder = BaseResponder()
        await WitnessRequestHandler().handle(context, responder)

        witness_proof = {}
        context = RequestContext(
            message=WitnessResponse(
                state=WitnessingState.SUCCESS,
                document=TEST_RECORD,
                witness_proof=witness_proof,
            )
        )
        await WitnessResponseHandler().handle(context, responder)

    @mock.patch(
        "aiohttp.ClientSession.post",
        mock.AsyncMock(
            return_value=mock.MagicMock(json=mock.AsyncMock(return_value={"results": []}))
        ),
    )
    async def test_routes():
        request = {}
        await get_pending_attested_resources(request)
        await approve_pending_attested_resource(request)
        await reject_pending_attested_resource(request)
