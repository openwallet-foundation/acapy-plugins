from unittest import IsolatedAsyncioTestCase
import uuid
from unittest import mock

from acapy_agent.core.event_bus import EventBus
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.protocols.coordinate_mediation.v1_0.route_manager import RouteManager
from acapy_agent.resolver.base import ResolutionMetadata, ResolutionResult, ResolverType
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.wallet.keys.manager import MultikeyManager

from ...config.config import set_config
from ..controller import ControllerManager
from ..witness import WitnessManager
from ..exceptions import ConfigurationError
from ...protocols.states import WitnessingState
from ...protocols.log_entry.record import PendingLogEntryRecord

SCID_PLACEHOLDER = "{SCID}"
TEST_DOMAIN = "sandbox.bcvh.vonx.io"
TEST_NAMESPACE = "test"
TEST_IDENTIFIER = "123"
TEST_VERSION_TIME = "2025-07-28T21:47:32Z"
TEST_SCID = "QmSFKAR8VfvU2NF1FpCFbUFakvJ6fDvLWcm4hQNwn8ZxEr"
TEST_DID = f"did:webvh:{TEST_SCID}:{TEST_DOMAIN}:{TEST_NAMESPACE}:{TEST_IDENTIFIER}"
TEST_VERSION_ID = "1-QmbnyKhBPuV93yvZn4N3RQrgiY11aSt86X4Hvuq98j5uLk"
TEST_WITNESS_KEY = "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i"
TEST_WITNESS_SEED = "00000000000000000000000000000000"
TEST_UPDATE_KEY = "z6Mkp2j8Zgm8CXMe4kvzWVsVnPzTQbBn2845CRpLLJChohyk"
TEST_SIGNING_KEY = "z6MkuH74MNE5CUVPTCb4ZJWpLyEE4RxVqKJeRP8E8BigksRa"
TEST_RESOLVER = mock.MagicMock(DIDResolver, autospec=True)
TEST_RESOLVER.resolve_with_metadata = mock.AsyncMock(
    return_value=ResolutionResult(
        did_document={},
        metadata=ResolutionMetadata(
            resolver_type=ResolverType.NATIVE,
            resolver="resolver",
            retrieved_time="retrieved_time",
            duration=0,
        ),
    )
)

TEST_NS_REQUEST_RESPONSE = {
    "versionId": SCID_PLACEHOLDER,
    "versionTime": TEST_VERSION_TIME,
    "parameters": {
        "scid": SCID_PLACEHOLDER,
        "method": "did:webvh:1.0",
        "updateKeys": [],
        "witness": {
            "threshold": 1,
            "witnesses": [{"id": f"did:key:{TEST_WITNESS_KEY}"}],
        },
    },
    "state": {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": f"did:webvh:{SCID_PLACEHOLDER}:{TEST_DOMAIN}:{TEST_NAMESPACE}:{TEST_IDENTIFIER}",
    },
    "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "proofPurpose": "assertionMethod",
    },
}

TEST_LOG_ENTRY = {
    "versionId": TEST_VERSION_ID,
    "versionTime": TEST_VERSION_TIME,
    "parameters": {
        "scid": TEST_SCID,
        "method": "did:webvh:1.0",
        "updateKeys": [TEST_UPDATE_KEY],
        "witness": {
            "threshold": 1,
            "witnesses": [{"id": f"did:key:{TEST_WITNESS_KEY}"}],
        },
    },
    "state": {
        "@context": ["https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1"],
        "id": TEST_DID,
        "verificationMethod": [
            {
                "id": f"{TEST_DID}#{TEST_SIGNING_KEY}",
                "type": "Multikey",
                "controller": TEST_DID,
                "publicKeyMultibase": TEST_SIGNING_KEY,
            }
        ],
        "authentication": [f"{TEST_DID}#{TEST_SIGNING_KEY}"],
        "assertionMethod": [f"{TEST_DID}#{TEST_SIGNING_KEY}"],
    },
    "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "proofPurpose": "assertionMethod",
        "proofValue": "z4B4Mk5jmEPWPotkMU1XWh7acd6HjPLNotshHKZE8g2sjRsVPoCmh48WqpCU5vwQLw6qnvpyWxKJVSzyRK7rkNNzR",
        "verificationMethod": f"did:key:{TEST_UPDATE_KEY}#{TEST_UPDATE_KEY}",
    },
}

ns_request_response = mock.AsyncMock(
    return_value=mock.MagicMock(
        json=mock.AsyncMock(return_value=TEST_NS_REQUEST_RESPONSE)
    )
)

request_namespace_fail = mock.AsyncMock(
    return_value=mock.MagicMock(
        status=400,
        json=mock.AsyncMock(
            return_value={
                "detail": {
                    "code": "invalid_request",
                    "description": "Invalid request",
                }
            }
        ),
    )
)

create_options = {"namespace": "test"}


class TestOperationsManager(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile({"wallet.type": "askar-anoncreds"})
        self.profile.context.injector.bind_instance(
            BaseResponder, mock.AsyncMock(BaseResponder, autospec=True)
        )
        self.profile.context.injector.bind_instance(DIDResolver, TEST_RESOLVER)
        self.profile.context.injector.bind_instance(EventBus, EventBus())
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.profile.context.injector.bind_instance(
            RouteManager, mock.AsyncMock(RouteManager, autospec=True)
        )
        self.profile.settings.set_value(
            "plugin_config", {"webvh": {"server_url": f"https://{TEST_DOMAIN}"}}
        )
        self.controller = ControllerManager(self.profile)
        self.witness = WitnessManager(self.profile)
        async with self.profile.session() as session:
            # Create known witness key for test server
            await MultikeyManager(session).create(
                alg="ed25519",
                kid=f"webvh:{TEST_DOMAIN}@witnessKey",
                seed=TEST_WITNESS_SEED,
            )

    async def test_create_invalid(self):
        await set_config(self.profile, {"server_url": None})
        # No server url
        with self.assertRaises(ConfigurationError):
            await self.controller.create(options={})

    @mock.patch("webvh.did.server_client.WebVHServerClient.request_identifier")
    @mock.patch("webvh.did.server_client.WebVHServerClient.submit_log_entry")
    async def test_create_self_witness(
        self, mock_submit_log_entry, mock_request_identifier
    ):
        await set_config(self.profile, {"server_url": f"https://{TEST_DOMAIN}"})

        # Mock server_client.request_identifier to return valid response
        # The identifier will be generated dynamically, so we need to capture it
        # Note: The code expects {SCID} placeholder in the document ID
        async def mock_request_identifier_impl(namespace, identifier):
            return {
                "versionId": SCID_PLACEHOLDER,
                "versionTime": TEST_VERSION_TIME,
                "parameters": {
                    "scid": SCID_PLACEHOLDER,
                    "method": "did:webvh:1.0",
                    "updateKeys": [],
                    "witness": {
                        "threshold": 1,
                        "witnesses": [{"id": f"did:key:{TEST_WITNESS_KEY}"}],
                    },
                },
                "state": {
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": f"did:webvh:{SCID_PLACEHOLDER}:{TEST_DOMAIN}:{namespace}:{identifier}",
                },
                "proof": {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "proofPurpose": "assertionMethod",
                },
            }

        mock_request_identifier.side_effect = mock_request_identifier_impl

        # Mock server_client.submit_log_entry
        async def mock_submit_log_entry_impl(*args, **kwargs):
            return {"state": {"id": TEST_DID}}

        mock_submit_log_entry.side_effect = mock_submit_log_entry_impl

        # Mock witness connection setup to avoid connection attempts
        mock_setup = mock.AsyncMock(return_value=None)
        self.controller.witness_connection.setup = mock_setup

        # Configure witness key
        await self.controller.configure(config={"auto_attest": True, "witness": True})

        # Create DID
        await self.controller.create(options={"namespace": TEST_NAMESPACE})

    @mock.patch("webvh.did.connection.OutOfBandManager")
    @mock.patch("webvh.did.connection.WebVHServerClient")
    @mock.patch("asyncio.sleep", new_callable=mock.AsyncMock)
    async def test_connect_to_witness_uses_server_service(
        self, _mock_sleep, mock_server_client_class, mock_oob_manager
    ):
        desired_witness_id = f"did:key:{TEST_WITNESS_KEY}"
        mock_receive = mock.AsyncMock()
        mock_oob_manager.return_value.receive_invitation = mock_receive

        # Mock the server client
        mock_server_client = mock.MagicMock()
        mock_server_client.get_witness_invitation = mock.AsyncMock(
            return_value={
                "goal": desired_witness_id,
                "goal-code": "witness-service",
            }
        )
        mock_server_client_class.return_value = mock_server_client

        connection_checker = mock.AsyncMock(side_effect=[None, mock.MagicMock()])
        with mock.patch.object(
            self.controller.witness_connection,
            "get_active_connection",
            connection_checker,
        ):
            result = await self.controller.witness_connection.connect(
                witness_id=desired_witness_id
            )

        mock_server_client.get_witness_invitation.assert_awaited_once_with(
            desired_witness_id
        )
        mock_receive.assert_awaited_once()
        assert result == desired_witness_id

    @mock.patch("asyncio.sleep", mock.AsyncMock())
    @mock.patch(
        "aiohttp.ClientSession.post",
        mock.AsyncMock(
            return_value=mock.MagicMock(
                json=mock.AsyncMock(
                    return_value={
                        "state": {"id": TEST_DID},
                    }
                )
            )
        ),
    )
    async def test_finish_create(self):
        await set_config(self.profile, {"server_url": f"https://{TEST_DOMAIN}"})

        # Has pending dids - attested
        record_id = str(uuid.uuid4())
        await PendingLogEntryRecord().save_pending_record(
            self.profile, TEST_SCID, TEST_LOG_ENTRY, record_id
        )
        await PendingLogEntryRecord().set_pending_record_id(
            self.profile,
            record_id,
        )

        witness_signature = await self.witness.sign(
            {"versionId": TEST_LOG_ENTRY.get("versionId")}
        )
        await self.controller.finish_did_operation(
            log_entry=TEST_LOG_ENTRY,
            witness_signature=witness_signature,
            state=WitnessingState.ATTESTED.value,
            record_id=record_id,
        )
        assert record_id not in (
            await PendingLogEntryRecord().get_pending_record_ids(self.profile)
        )
