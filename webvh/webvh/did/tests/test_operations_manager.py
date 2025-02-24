from unittest import IsolatedAsyncioTestCase

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.core.event_bus import EventBus
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.resolver.base import ResolutionMetadata, ResolutionResult, ResolverType
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.wallet.keys.manager import MultikeyManager
from aiohttp import ClientConnectionError

from ...config.config import set_config
from ..exceptions import ConfigurationError, DidCreationError, WitnessError
from ..operations_manager import DidWebvhOperationsManager
from ..pending_dids import PendingWebvhDids
from ..registration_state import RegistrationState

log_entry_response = {
    "logEntry": {
        "versionId": "1-QmSV77yftroggmtFuUrTDQaHaxpKwDwPvKwkhLqkS1hucT",
        "versionTime": "2024-12-18T21:15:58",
        "parameters": {
            "updateKeys": ["z6MktZNLyY8wGFu9bKX3428Uzsocotpm9LWvVY4R3vkeHKxP"],
            "method": "did:webvh:0.4",
            "scid": "QmVSevWDZeaFYcTx2FaVaU91G9ABtyEW5vG3wzKTxN7cuS",
        },
        "state": {
            "@context": ["..."],
            "id": "did:webvh:QmVSevWDZeaFYcTx2FaVaU91G9ABtyEW5vG3wzKTxN7cuS:id.test-suite.app:prod:3",
            "verificationMethod": ["..."],
            "authentication": ["..."],
            "assertionMethod": ["..."],
        },
    }
}

initial_create_response = {
    "state": {
        "id": "did:webvh:QmVSevWDZeaFYcTx2FaVaU91G9ABtyEW5vG3wzKTxN7cuS:id.test-suite.app:prod:3",
    }
}

request_namespace = mock.AsyncMock(
    return_value=mock.MagicMock(
        json=mock.AsyncMock(
            return_value={
                "didDocument": {
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "did:web:id.test-suite.app:prod:1",
                },
                "proofOptions": {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "proofPurpose": "assertionMethod",
                    "expires": "2024-12-18T20:46:01+00:00",
                    "domain": "id.test-suite.app",
                    "challenge": "fa0b6142-cd83-576b-a7a7-5cc4eb10e0ea",
                },
            }
        )
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


class TestOperationsManager(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile({"wallet.type": "askar-anoncreds"})
        async with self.profile.session() as session:
            await MultikeyManager(session).create(
                alg="ed25519",
                kid="webvh:id.test-suite.app@witnessKey",
            )

    async def test_create_invalid(self):
        self.profile.settings.set_value(
            "plugin_config", {"did-webvh": {"role": "controller"}}
        )
        # No server url
        with self.assertRaises(ConfigurationError):
            await DidWebvhOperationsManager(self.profile).create(options={})

    @mock.patch(
        "aiohttp.ClientSession.get",
        request_namespace,
    )
    @mock.patch(
        "aiohttp.ClientSession.post",
        mock.AsyncMock(
            return_value=mock.MagicMock(
                json=mock.AsyncMock(
                    side_effect=[log_entry_response, initial_create_response]
                )
            )
        ),
    )
    async def test_create_self_witness(self):
        self.profile.settings.set_value(
            "plugin_config",
            {"did-webvh": {"server_url": "http://id.test-suite.app"}},
        )

        resolver = mock.MagicMock(DIDResolver, autospec=True)
        resolver.resolve_with_metadata = mock.AsyncMock(
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
        self.profile.context.injector.bind_instance(DIDResolver, resolver)
        self.profile.context.injector.bind_instance(EventBus, EventBus())
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())

        await DidWebvhOperationsManager(self.profile).create(
            options={"namespace": "test"}
        )

    @mock.patch(
        "aiohttp.ClientSession.get",
        request_namespace,
    )
    @mock.patch(
        "aiohttp.ClientSession.post",
        mock.AsyncMock(
            return_value=mock.MagicMock(
                json=mock.AsyncMock(
                    side_effect=[
                        log_entry_response,
                        initial_create_response,
                        log_entry_response,
                        {
                            "state": {
                                "id": "did:webvh:QmVSevWDZeaFYcTx2FaVaU91G9ABtyEW5vG3wzKTxN7cuS:id.test-suite.app:prod:4",
                            }
                        },
                    ]
                )
            )
        ),
    )
    async def test_create_self_witness_as_witness(self):
        self.profile.settings.set_value(
            "plugin_config",
            {"did-webvh": {"server_url": "http://id.test-suite.app", "role": "witness"}},
        )

        resolver = mock.MagicMock(DIDResolver, autospec=True)
        resolver.resolve_with_metadata = mock.AsyncMock(
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
        self.profile.context.injector.bind_instance(DIDResolver, resolver)
        self.profile.context.injector.bind_instance(EventBus, EventBus())
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())

        await DidWebvhOperationsManager(self.profile).create(
            options={"namespace": "test"}
        )

        # Same thing with existing key now
        await DidWebvhOperationsManager(self.profile).create(
            options={"namespace": "test"}
        )

    @mock.patch(
        "aiohttp.ClientSession.get",
        request_namespace,
    )
    async def test_create_as_controller(self):
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "server_url": "http://id.test-suite.app",
                    "role": "controller",
                }
            },
        )
        self.profile.context.injector.bind_instance(
            BaseResponder, mock.AsyncMock(BaseResponder, autospec=True)
        )
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.profile.context.injector.bind_instance(EventBus, EventBus())

        # No active connection
        with self.assertRaises(WitnessError):
            await DidWebvhOperationsManager(self.profile).create(
                options={"namespace": "test"}
            )

        # Has connection
        async with self.profile.session() as session:
            record = ConnRecord(
                alias="webvh:id.test-suite.app@witness",
                state="active",
            )
            await record.save(session)

        await DidWebvhOperationsManager(self.profile).create(
            options={"namespace": "test"}
        )
        await DidWebvhOperationsManager(self.profile).finish_create(
            witnessed_document={"id": "did:web:id.test-suite.app:prod:1"},
            parameters={},
            state=RegistrationState.PENDING.value,
            authorized_key_info=None,
        )

    @mock.patch(
        "aiohttp.ClientSession.get",
        side_effect=[ClientConnectionError()],
    )
    async def test_create_connection_error_with_server(self, _):
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "server_url": "http://id.test-suite.app",
                    "role": "controller",
                }
            },
        )
        with self.assertRaises(DidCreationError):
            await DidWebvhOperationsManager(self.profile).create(
                options={"namespace": "test"}
            )

    @mock.patch("aiohttp.ClientSession.get", request_namespace_fail)
    async def test_create_bad_request(self):
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "server_url": "http://id.test-suite.app",
                }
            },
        )

        with self.assertRaises(DidCreationError):
            await DidWebvhOperationsManager(self.profile).create(
                options={"namespace": "test"}
            )

    @mock.patch(
        "aiohttp.ClientSession.get",
        mock.AsyncMock(
            return_value=mock.MagicMock(
                json=mock.AsyncMock(
                    return_value={
                        "didDocument": {
                            "@context": ["https://www.w3.org/ns/did/v1"],
                            "id": "did:web:id.test-suite.app:prod:1",
                        },
                        "proofOptions": {
                            "type": "DataIntegrityProof",
                            "cryptosuite": "eddsa-jcs-2022",
                            "proofPurpose": "assertionMethod",
                            "expires": "2024-12-18T20:46:01+00:00",
                            # "domain": "id.test-suite.app",
                            "challenge": "fa0b6142-cd83-576b-a7a7-5cc4eb10e0ea",
                        },
                    }
                )
            )
        ),
    )
    async def test_create_response_is_missing_required_value(self):
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "server_url": "http://id.test-suite.app",
                    "role": "witness",
                }
            },
        )

        with self.assertRaises(DidCreationError):
            await DidWebvhOperationsManager(self.profile).create(
                options={"namespace": "test"}
            )

    @mock.patch("asyncio.sleep", mock.AsyncMock())
    @mock.patch(
        "aiohttp.ClientSession.post",
        mock.AsyncMock(
            return_value=mock.MagicMock(
                json=mock.AsyncMock(
                    return_value={
                        # For first response
                        "didDocument": {
                            "@context": ["https://www.w3.org/ns/did/v1"],
                            "id": "did:webvh:QmVSevWDZeaFYcTx2FaVaU91G9ABtyEW5vG3wzKTxN7cuS:id.test-suite.app:prod:3",
                        },
                        # For second response
                        "state": {
                            "id": "did:webvh:QmVSevWDZeaFYcTx2FaVaU91G9ABtyEW5vG3wzKTxN7cuS:id.test-suite.app:prod:3"
                        },
                    }
                )
            )
        ),
    )
    async def test_finish_create(self):
        self.profile.context.injector.bind_instance(EventBus, EventBus())
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.profile.context.injector.bind_instance(
            DIDResolver,
            mock.MagicMock(
                DIDResolver,
                autospec=True,
                resolve_with_metadata=mock.AsyncMock(
                    return_value=ResolutionResult(
                        did_document={},
                        metadata=ResolutionMetadata(
                            resolver_type=ResolverType.NATIVE,
                            resolver="resolver",
                            retrieved_time="retrieved_time",
                            duration=0,
                        ),
                    )
                ),
            ),
        )
        test_did = "did:webvh:QmVSevWDZeaFYcTx2FaVaU91G9ABtyEW5vG3wzKTxN7cuS:id.test-suite.app:prod:3"

        # No pending dids - attested
        await DidWebvhOperationsManager(self.profile).finish_create(
            witnessed_document={"id": test_did},
            parameters={},
            state=RegistrationState.ATTESTED.value,
            authorized_key_info=None,
        )

        # Pending state
        await DidWebvhOperationsManager(self.profile).finish_create(
            witnessed_document={"id": test_did},
            parameters={},
            state=RegistrationState.PENDING.value,
            authorized_key_info=None,
        )

        # Has pending dids - attested
        await PendingWebvhDids().set_pending_did(
            self.profile,
            test_did,
        )

        await set_config(
            self.profile,
            {
                "server_url": "http://id.test-suite.app",
                "role": "controller",
            },
        )

        async with self.profile.session() as session:
            await MultikeyManager(session).create(
                alg="ed25519",
                kid=f"webvh:{test_did}@updateKey",
            )

        await DidWebvhOperationsManager(self.profile).finish_create(
            witnessed_document={
                "id": test_did,
                "proof": [{"domain": "id.test-suite.app"}],
            },
            parameters={},
            state=RegistrationState.ATTESTED.value,
            authorized_key_info=None,
        )
        assert test_did not in (await PendingWebvhDids().get_pending_dids(self.profile))
