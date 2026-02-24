from unittest import IsolatedAsyncioTestCase
import uuid

from acapy_agent.core.event_bus import EventBus
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.resolver.base import ResolutionMetadata, ResolutionResult, ResolverType
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.wallet.keys.manager import MultikeyManager

from ...config.config import set_config
from ..manager import ControllerManager
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

    async def test_create_self_witness(self):
        await set_config(self.profile, {"server_url": f"https://{TEST_DOMAIN}"})

        # Configure witness key
        await self.controller.configure(options={"auto_attest": True, "witness": True})

        # Create DID
        await self.controller.create(options={"namespace": TEST_NAMESPACE})

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

        witness_signature = await self.witness.sign_log_version(
            TEST_LOG_ENTRY.get("versionId")
        )
        await self.controller.finish_did_operation(
            log_entry=TEST_LOG_ENTRY,
            witness_signature=witness_signature,
            state=WitnessingState.ATTESTED.value,
            record_id=record_id,
        )
        # Record is removed by handler; verify we can clean up
        await PendingLogEntryRecord().remove_pending_record(self.profile, record_id)
        results = await PendingLogEntryRecord().get_pending_records(self.profile)
        assert not any(r.get("record_id") == record_id for r in results)

    @mock.patch("webvh.did.manager.is_witness", mock.AsyncMock(return_value=True))
    async def test_controller_saves_request_on_witness_signature(self):
        """Verify controller saves pending request in _request_witness_signature."""
        await set_config(self.profile, {"server_url": f"https://{TEST_DOMAIN}"})

        request_id = str(uuid.uuid4())
        result = await self.controller._request_witness_signature(
            request_id, log_entry=TEST_LOG_ENTRY, scid=TEST_SCID
        )

        assert result.get("status") == WitnessingState.PENDING.value

        results = await PendingLogEntryRecord().get_pending_records(self.profile)
        assert any(r.get("record_id") == request_id for r in results)
        record = next(r for r in results if r.get("record_id") == request_id)
        assert record.get("scid") == TEST_SCID
        assert record.get("role") == "self-witness"
        assert record.get("state") == WitnessingState.PENDING.value

        await PendingLogEntryRecord().remove_pending_record(self.profile, request_id)
