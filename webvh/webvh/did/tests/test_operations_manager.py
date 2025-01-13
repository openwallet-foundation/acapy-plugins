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

from ..exceptions import ConfigurationError, DidCreationError, EndorsementError
from ..operations_manager import DidWebvhOperationsManager

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
            "id": "did:webvh:QmVSevWDZeaFYcTx2FaVaU91G9ABtyEW5vG3wzKTxN7cuS:server.localhost%3A8000:prod:3",
            "verificationMethod": ["..."],
            "authentication": ["..."],
            "assertionMethod": ["..."],
        },
    }
}

initial_create_response = {
    "state": {
        "id": "did:webvh:QmVSevWDZeaFYcTx2FaVaU91G9ABtyEW5vG3wzKTxN7cuS:server.localhost%3A8000:prod:3",
    }
}

request_namespace = mock.AsyncMock(
    return_value=mock.MagicMock(
        json=mock.AsyncMock(
            return_value={
                "didDocument": {
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "did:web:server.localhost%3A8000:prod:1",
                },
                "proofOptions": {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "proofPurpose": "assertionMethod",
                    "expires": "2024-12-18T20:46:01+00:00",
                    "domain": "server.localhost%3A8000",
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

    async def test_create_invalid(self):
        self.profile.settings.set_value(
            "plugin_config", {"did-webvh": {"role": "controller"}}
        )
        # No server url
        with self.assertRaises(ConfigurationError):
            await DidWebvhOperationsManager(self.profile).create(options={})

        self.profile.settings.set_value(
            "plugin_config",
            {"did-webvh": {"role": "controller", "server_url": "http://localhost:8000"}},
        )
        # No namespace
        with self.assertRaises(DidCreationError):
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
    async def test_create_self_endorsement(self):
        self.profile.settings.set_value(
            "plugin_config",
            {"did-webvh": {"server_url": "http://localhost:8000"}},
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
        self.profile.context.injector.bind_instance(
            EventBus, mock.MagicMock(EventBus, autospec=True)
        )

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
                                "id": "did:webvh:QmVSevWDZeaFYcTx2FaVaU91G9ABtyEW5vG3wzKTxN7cuS:server.localhost%3A8000:prod:4",
                            }
                        },
                    ]
                )
            )
        ),
    )
    async def test_create_self_endorsement_as_endorser(self):
        self.profile.settings.set_value(
            "plugin_config",
            {"did-webvh": {"server_url": "http://localhost:8000", "role": "endorser"}},
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
        self.profile.context.injector.bind_instance(
            EventBus, mock.MagicMock(EventBus, autospec=True)
        )
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
    @mock.patch.object(
        DidWebvhOperationsManager,
        "_wait_for_endorsement",
        mock.AsyncMock(return_value=None),
    )
    async def test_create_as_controller(self):
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "server_url": "http://localhost:8000",
                    "role": "controller",
                }
            },
        )
        self.profile.context.injector.bind_instance(
            BaseResponder, mock.AsyncMock(BaseResponder, autospec=True)
        )
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())

        # No active connection
        with self.assertRaises(EndorsementError):
            await DidWebvhOperationsManager(self.profile).create(
                options={"namespace": "test"}
            )

        # Has connection
        async with self.profile.session() as session:
            record = ConnRecord(
                alias="http://localhost:8000-endorser",
                state="active",
            )
            await record.save(session)

        await DidWebvhOperationsManager(self.profile).create(
            options={"namespace": "test"}
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
                    "server_url": "http://localhost:8000",
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
                    "server_url": "http://localhost:8000",
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
                            "id": "did:web:server.localhost%3A8000:prod:1",
                        },
                        "proofOptions": {
                            "type": "DataIntegrityProof",
                            "cryptosuite": "eddsa-jcs-2022",
                            "proofPurpose": "assertionMethod",
                            "expires": "2024-12-18T20:46:01+00:00",
                            # "domain": "server.localhost%3A8000",
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
                    "server_url": "http://localhost:8000",
                    "role": "endorser",
                }
            },
        )

        with self.assertRaises(DidCreationError):
            await DidWebvhOperationsManager(self.profile).create(
                options={"namespace": "test"}
            )

    @mock.patch(
        "aiohttp.ClientSession.get",
        request_namespace,
    )
    @mock.patch.object(
        DidWebvhOperationsManager,
        "_wait_for_endorsement",
        mock.AsyncMock(return_value=None),
    )
    async def test_create_as_controller_with_existing_key(self):
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "server_url": "http://localhost:8000",
                    "role": "controller",
                }
            },
        )
        responder = mock.AsyncMock(BaseResponder, autospec=True)
        responder.send = mock.AsyncMock(return_value=None)
        self.profile.context.injector.bind_instance(BaseResponder, responder)
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())

        async with self.profile.session() as session:
            record = ConnRecord(
                alias="http://localhost:8000-endorser",
                state="active",
            )
            await record.save(session)
            await MultikeyManager(session).create(
                alg="ed25519",
                kid="did:web:server.localhost%3A8000:prod:1#authorized",
            )

        await DidWebvhOperationsManager(self.profile).create(
            options={"namespace": "test"}
        )
