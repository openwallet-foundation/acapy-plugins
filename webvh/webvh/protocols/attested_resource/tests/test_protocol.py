from unittest import IsolatedAsyncioTestCase
import uuid

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.core.event_bus import EventBus
from acapy_agent.messaging.request_context import RequestContext
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.keys.manager import MultikeyManager
from acapy_agent.wallet.key_type import KeyTypes

from ..handlers import WitnessRequestHandler, WitnessResponseHandler
from ..record import PendingAttestedResourceRecord
from ..messages import WitnessRequest, WitnessResponse
from ...states import WitnessingState
from ....tests.fixtures import TEST_RESOLVER

record = PendingAttestedResourceRecord()

TEST_DOMAIN = "example.com"
TEST_SCID = "123"
TEST_RECORD_ID = str(uuid.uuid4())
TEST_DID = f"did:webvh:{TEST_SCID}:{TEST_DOMAIN}:test:123"
TEST_RESOURCE_ID = f"{TEST_DID}/resources/123"
TEST_RECORD = {
    "id": TEST_RESOURCE_ID,
    "content": {"schema_name": "Test Schema"},
    "proof": [{"type": "DataIntegrityProof"}],
}


class TestAttestedResourceProtocol(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile({"wallet.type": "askar-anoncreds"})
        self.profile.settings.set_value(
            "plugin_config",
            {"did-webvh": {"server_url": "https://example.com"}},
        )
        self.profile.context.injector.bind_instance(
            BaseResponder, mock.AsyncMock(BaseResponder, autospec=True)
        )
        self.profile.context.injector.bind_instance(EventBus, EventBus())
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.profile.context.injector.bind_instance(DIDResolver, TEST_RESOLVER)
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
        await record.set_pending_record_id(self.profile, TEST_RECORD_ID)
        await record.get_pending_record_ids(self.profile)
        await record.remove_pending_record_id(self.profile, TEST_RECORD_ID)
        await record.get_pending_record_ids(self.profile)

        await record.save_pending_record(
            self.profile, TEST_SCID, TEST_RECORD, TEST_RECORD_ID
        )
        await record.get_pending_records(self.profile)
        await record.get_pending_record(self.profile, TEST_RECORD_ID)
        await record.remove_pending_record(self.profile, TEST_RECORD_ID)

        with self.assertRaises(AttributeError):
            await record.get_pending_records(self.profile)
            await record.get_pending_record(self.profile, TEST_RECORD_ID)

    @mock.patch(
        "aiohttp.ClientSession.post",
        mock.AsyncMock(
            return_value=mock.MagicMock(
                json=mock.AsyncMock(
                    return_value={
                        "id": TEST_RESOURCE_ID,
                        "content": {},
                        "proof": {},
                    }
                )
            )
        ),
    )
    async def test_handler(self):
        self.profile.settings.set_value(
            "plugin_config",
            {"did-webvh": {"server_url": "https://example.com", "auto_attest": False}},
        )
        context = RequestContext(self.profile)
        request_id = str(uuid.uuid4())
        context.message = WitnessRequest(document=TEST_RECORD, request_id=request_id)
        context.connection_record = ConnRecord(
            alias=f"webvh:{TEST_DOMAIN}@witness",
            state="active",
            connection_id="123",
        )
        assert await WitnessRequestHandler().handle(
            context, mock.AsyncMock(BaseResponder, autospec=True)
        )

        witness_proof = {"type": "DataIntegrityProof"}
        context = RequestContext(self.profile)
        context.message = WitnessResponse(
            state=WitnessingState.SUCCESS.value,
            document=TEST_RECORD,
            witness_proof=witness_proof,
            request_id=request_id,
        )
        assert await WitnessResponseHandler().handle(
            context, mock.AsyncMock(BaseResponder, autospec=True)
        )
