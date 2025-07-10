import asyncio
from unittest import IsolatedAsyncioTestCase

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.protocols.coordinate_mediation.v1_0.route_manager import RouteManager
from acapy_agent.protocols.out_of_band.v1_0.manager import OutOfBandManager
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.wallet.keys.manager import MultikeyManager

from ..exceptions import ConfigurationError, WitnessError
from ..witness_manager import PENDING_DOCUMENT_TABLE_NAME, WitnessManager

mock_did_doc = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    "id": "did:web:id.test-suite.app:prod:38c35877-6b40-4ef2-b5dd-1b9154911604",
    "verificationMethod": [
        {
            "id": "did:web:id.test-suite.app:prod:38c35877-6b40-4ef2-b5dd-1b9154911604#key-01",
            "type": "Multikey",
            "controller": "did:web:id.test-suite.app:prod:38c35877-6b40-4ef2-b5dd-1b9154911604",
            "publicKeyMultibase": "z6MkrkHx84xReNNx2oK9Hefr7CtnQeVEEKrcpSCtoNhBVGJV",
        }
    ],
    "authentication": [
        "did:web:id.test-suite.app:prod:38c35877-6b40-4ef2-b5dd-1b9154911604#key-01"
    ],
    "assertionMethod": [
        "did:web:id.test-suite.app:prod:38c35877-6b40-4ef2-b5dd-1b9154911604#key-01"
    ],
    "proof": [
        {
            "type": "DataIntegrityProof",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:key:z6MkqY5kWa85eTgHsN6uRSRWxgAoxi5CHz1onvqrPNTqgvwe#z6MkqY5kWa85eTgHsN6uRSRWxgAoxi5CHz1onvqrPNTqgvwe",
            "cryptosuite": "eddsa-jcs-2022",
            "expires": "2025-02-22T00:56:48+00:00",
            "domain": "id.test-suite.app",
            "challenge": "7f005295-a8e7-5eee-b43d-c2a6167d2d6b",
            "proofValue": "z2bmbwqbziW3BYLt6vJQ5A5qmcuBqn8HGhPua4CFzsbAPKHTrG8yHRd75mJtmDN1iXFLRBUp1Zsf8GLPjpwP2xuhz",
        }
    ],
}


class TestWitnessManager(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile({"wallet.type": "askar-anoncreds"})
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.profile.context.injector.bind_instance(
            BaseResponder, mock.MagicMock(BaseResponder, autospec=True)
        )

    @mock.patch.object(WitnessManager, "_get_active_witness_connection")
    async def test_auto_witness_setup_as_witness(
        self, mock_get_active_witness_connection
    ):
        self.profile.settings.set_value(
            "plugin_config",
            {"did-webvh": {"role": "witness", "server_url": "https://id.test-suite.app"}},
        )
        await WitnessManager(self.profile).auto_witness_setup()
        assert not mock_get_active_witness_connection.called

    async def test_auto_witness_setup_as_controller_no_server_url(self):
        self.profile.settings.set_value(
            "plugin_config",
            {"did-webvh": {"role": "controller"}},
        )
        with self.assertRaises(ConfigurationError):
            await WitnessManager(self.profile).auto_witness_setup()

    async def test_auto_witness_setup_as_controller_with_previous_connection(self):
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "role": "controller",
                    "server_url": "https://id.test-suite.app",
                }
            },
        )
        async with self.profile.session() as session:
            record = ConnRecord(
                alias="https://id.test-suite.app@Witness",
                state="active",
            )
            await record.save(session)
        await WitnessManager(self.profile).auto_witness_setup()

    async def test_auto_witness_setup_as_controller_no_witness_invitation(self):
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "role": "controller",
                    "server_url": "https://id.test-suite.app",
                }
            },
        )
        await WitnessManager(self.profile).auto_witness_setup()

    @mock.patch.object(OutOfBandManager, "receive_invitation")
    async def test_auto_witness_setup_as_controller_bad_invitation(
        self, mock_receive_invitation
    ):
        self.profile.settings.set_value("plugin_config.did-webvh.role", "controller")
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "role": "controller",
                    "server_url": "https://id.test-suite.app",
                    "witness_invitation": "http://witness:9050?oob=eyJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL291dC1vZi1iYW5kLzEuMS9pbnZpdGF0aW9uIiwgIkBpZCI6ICIwZDkwMGVjMC0wYzE3LTRmMTYtOTg1ZC1mYzU5MzVlYThjYTkiLCAibGFiZWwiOiAidGR3LWVuZG9yc2VyIiwgImhhbmRzaGFrZV9wcm90b2NvbHMiOiBbImh0dHBzOi8vZGlkY29tbS5vcmcvZGlkZXhjaGFuZ2UvMS4wIl0sICJzZXJ2aWNlcyI6IFt7ImlkIjogIiNpbmxpbmUiLCAidHlwZSI6ICJkaWQtY29tbXVuaWNhdGlvbiIsICJyZWNpcGllbnRLZXlzIjogWyJkaWQ6a2V5Ono2TWt0bXJUQURBWWRlc2Ftb3F1ZVV4NHNWM0g1Mms5b2ZoQXZRZVFaUG9vdTE3ZSN6Nk1rdG1yVEFEQVlkZXNhbW9xdWVVeDRzVjNINTJrOW9maEF2UWVRWlBvb3UxN2UiXSwgInNlcnZpY2VFbmRwb2ludCI6ICJodHRwOi8vbG9jYWxob3N0OjkwNTAifV19",
                }
            },
        )
        self.profile.context.injector.bind_instance(
            RouteManager, mock.AsyncMock(RouteManager, autospec=True)
        )
        mock_receive_invitation.side_effect = BaseModelError("Bad invitation")
        with self.assertRaises(WitnessError):
            await WitnessManager(self.profile).auto_witness_setup()

    @mock.patch.object(OutOfBandManager, "receive_invitation")
    @mock.patch.object(asyncio, "sleep")
    async def test_auto_witness_setup_as_controller_no_active_connection(self, *_):
        self.profile.settings.set_value("plugin_config.did-webvh.role", "controller")
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "role": "controller",
                    "server_url": "https://id.test-suite.app",
                    "witness_invitation": "http://witness:9050?oob=eyJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL291dC1vZi1iYW5kLzEuMS9pbnZpdGF0aW9uIiwgIkBpZCI6ICIwZDkwMGVjMC0wYzE3LTRmMTYtOTg1ZC1mYzU5MzVlYThjYTkiLCAibGFiZWwiOiAidGR3LWVuZG9yc2VyIiwgImhhbmRzaGFrZV9wcm90b2NvbHMiOiBbImh0dHBzOi8vZGlkY29tbS5vcmcvZGlkZXhjaGFuZ2UvMS4wIl0sICJzZXJ2aWNlcyI6IFt7ImlkIjogIiNpbmxpbmUiLCAidHlwZSI6ICJkaWQtY29tbXVuaWNhdGlvbiIsICJyZWNpcGllbnRLZXlzIjogWyJkaWQ6a2V5Ono2TWt0bXJUQURBWWRlc2Ftb3F1ZVV4NHNWM0g1Mms5b2ZoQXZRZVFaUG9vdTE3ZSN6Nk1rdG1yVEFEQVlkZXNhbW9xdWVVeDRzVjNINTJrOW9maEF2UWVRWlBvb3UxN2UiXSwgInNlcnZpY2VFbmRwb2ludCI6ICJodHRwOi8vbG9jYWxob3N0OjkwNTAifV19",
                }
            },
        )
        self.profile.context.injector.bind_instance(
            RouteManager, mock.AsyncMock(RouteManager, autospec=True)
        )
        await WitnessManager(self.profile).auto_witness_setup()

    @mock.patch.object(OutOfBandManager, "receive_invitation")
    async def test_auto_witness_setup_as_controller_conn_becomes_active(self, *_):
        self.profile.settings.set_value("plugin_config.did-webvh.role", "controller")
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "role": "controller",
                    "server_url": "https://id.test-suite.app",
                    "witness_invitation": "http://witness:9050?oob=eyJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL291dC1vZi1iYW5kLzEuMS9pbnZpdGF0aW9uIiwgIkBpZCI6ICIwZDkwMGVjMC0wYzE3LTRmMTYtOTg1ZC1mYzU5MzVlYThjYTkiLCAibGFiZWwiOiAidGR3LWVuZG9yc2VyIiwgImhhbmRzaGFrZV9wcm90b2NvbHMiOiBbImh0dHBzOi8vZGlkY29tbS5vcmcvZGlkZXhjaGFuZ2UvMS4wIl0sICJzZXJ2aWNlcyI6IFt7ImlkIjogIiNpbmxpbmUiLCAidHlwZSI6ICJkaWQtY29tbXVuaWNhdGlvbiIsICJyZWNpcGllbnRLZXlzIjogWyJkaWQ6a2V5Ono2TWt0bXJUQURBWWRlc2Ftb3F1ZVV4NHNWM0g1Mms5b2ZoQXZRZVFaUG9vdTE3ZSN6Nk1rdG1yVEFEQVlkZXNhbW9xdWVVeDRzVjNINTJrOW9maEF2UWVRWlBvb3UxN2UiXSwgInNlcnZpY2VFbmRwb2ludCI6ICJodHRwOi8vbG9jYWxob3N0OjkwNTAifV19",
                }
            },
        )
        self.profile.context.injector.bind_instance(
            RouteManager, mock.AsyncMock(RouteManager, autospec=True)
        )

        async def _create_connection():
            await asyncio.sleep(1)
            async with self.profile.session() as session:
                record = ConnRecord(
                    alias="https://id.test-suite.app@Witness",
                    state="active",
                )
                await record.save(session)

        asyncio.create_task(_create_connection())
        await WitnessManager(self.profile).auto_witness_setup()

    async def test_attest_did_request_doc_no_doc(self):
        with self.assertRaises(WitnessError):
            await WitnessManager(self.profile).attest_did_request_doc("test-id")

    async def test_attest_did_request_doc_no_proof(self):
        mock_did_doc.pop("proof")
        async with self.profile.session() as session:
            await session.handle.insert(
                PENDING_DOCUMENT_TABLE_NAME,
                "test-id",
                value_json=mock_did_doc,
            )
        with self.assertRaises(WitnessError):
            await WitnessManager(self.profile).attest_did_request_doc("test-id")

    async def test_attest_did_request_doc_no_witness_key(self):
        async with self.profile.session() as session:
            await session.handle.insert(
                PENDING_DOCUMENT_TABLE_NAME,
                "test-id",
                value_json=mock_did_doc,
            )
        with self.assertRaises(WitnessError):
            await WitnessManager(self.profile).attest_did_request_doc("test-id")

    async def test_attest_did_request_doc(self):
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "role": "controller",
                    "server_url": "https://id.test-suite.app",
                }
            },
        )

        async with self.profile.session() as session:
            await MultikeyManager(session).create(
                alg="ed25519",
                kid="webvh:id.test-suite.app@witnessKey",
            )
            await session.handle.insert(
                PENDING_DOCUMENT_TABLE_NAME,
                "test-id",
                value_json=mock_did_doc,
                tags={"connection_id": "test-conn-id"},
            )

        result = await WitnessManager(self.profile).attest_did_request_doc("test-id")
        assert result["status"] == "success"
        assert self.profile.context.injector.get_provider(
            BaseResponder
        )._instance.send.called

        async with self.profile.session() as session:
            record = await session.handle.fetch(
                PENDING_DOCUMENT_TABLE_NAME,
                "test-id",
            )
            assert record is None
