from unittest import IsolatedAsyncioTestCase

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.messaging.request_context import RequestContext
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.keys.manager import MultikeyManager
from acapy_agent.wallet.key_type import KeyTypes

from ..handlers import WitnessRequestHandler, WitnessResponseHandler
from ..record import PendingLogEntryRecord
from ..messages import WitnessRequest, WitnessResponse
from ..routes import (
    get_pending_log_entries,
    approve_pending_log_entry,
    reject_pending_log_entry,
)
from ...states import WitnessingState

record = PendingLogEntryRecord()

TEST_DOMAIN = "example.com"
TEST_SCID = "123"
TEST_RECORD = {
    "versionId": "1-Q",
    "parameters": {"scid": TEST_SCID},
    "state": {"id": f"did:webvh:{TEST_SCID}:{TEST_DOMAIN}"},
    "proof": {"type": "DataIntegrityProof"},
}


class TestLogEntryProtocol(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile({"wallet.type": "askar-anoncreds"})
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
        )
        async with self.profile.session() as session:
            # Create known witness key for test server
            await MultikeyManager(session).create(
                alg="ed25519",
                kid=f"webvh:{TEST_DOMAIN}@witnessKey",
                # seed=TEST_WITNESS_SEED,
            )

    async def test_record(self):
        await record.set_pending_scid(self.profile, TEST_SCID)
        await record.get_pending_scids(self.profile)
        await record.remove_pending_scid(self.profile, TEST_SCID)
        await record.get_pending_scids(self.profile)

        await record.save_pending_record(self.profile, TEST_SCID, TEST_RECORD)
        await record.get_pending_records(self.profile)
        await record.get_pending_record(self.profile, TEST_SCID)
        await record.remove_pending_record(self.profile, TEST_SCID)

        with self.assertRaises(AttributeError):
            await record.get_pending_records(self.profile)
            await record.get_pending_record(self.profile, TEST_SCID)

    async def test_handler(self):
        self.profile.settings.set_value(
            "plugin_config",
            {"did-webvh": {"server_url": "https://example.com", "auto_attest": False}},
        )
        context = RequestContext(self.profile)
        context.message = WitnessRequest(document=TEST_RECORD)
        context.connection_record = ConnRecord(
            alias=f"webvh:{TEST_DOMAIN}@witness",
            state="active",
            connection_id="123",
        )
        # await WitnessRequestHandler().handle(context, BaseResponder)

        # witness_proof = {
        #     "type": "DataIntegrityProof"
        # }
        # context = RequestContext(self.profile)
        # context.message = WitnessResponse(
        #     state=WitnessingState.SUCCESS.value,
        #     document=TEST_RECORD,
        #     witness_proof=witness_proof
        # )
        # await WitnessResponseHandler().handle(context, BaseResponder)
