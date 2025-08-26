import asyncio
from unittest import IsolatedAsyncioTestCase

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.protocols.coordinate_mediation.v1_0.route_manager import RouteManager
from acapy_agent.protocols.out_of_band.v1_0.manager import OutOfBandManager
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.wallet.keys.manager import MultikeyManager

from ..exceptions import ConfigurationError
from ..manager import ControllerManager
from ..witness import WitnessManager
from ...protocols.log_entry.record import PendingLogEntryRecord

PENDING_DOCUMENT_TABLE_NAME = PendingLogEntryRecord().RECORD_TYPE

SERVER_DOMAIN = "sandbox.bcvh.vonx.io"
SERVER_URL = f"https://{SERVER_DOMAIN}"


class TestWitnessManager(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile(
            {
                "wallet.type": "askar-anoncreds",
                "default_label": "Test",
                "default_endpoint": "https://example.com",
            }
        )
        self.profile.settings.set_value(
            "plugin_config",
            {"did-webvh": {"server_url": "https://example.com"}},
        )
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.profile.context.injector.bind_instance(
            BaseResponder, mock.MagicMock(BaseResponder, autospec=True)
        )
        self.profile.context.injector.bind_instance(
            RouteManager, mock.AsyncMock(RouteManager, autospec=True)
        )
        self.witness = WitnessManager(self.profile)
        self.controller = ControllerManager(self.profile)
        async with self.profile.session() as session:
            await MultikeyManager(session).create(
                alg="ed25519",
                kid="webvh:example.com@witnessKey",
            )

    async def test_witness_key_alias(self):
        assert await self.witness.key_alias()

    async def test_witness_connection_alias(self):
        assert await self.witness.connection_alias()

    @mock.patch.object(WitnessManager, "_get_active_witness_connection")
    async def test_auto_witness_setup_as_witness(
        self, mock_get_active_witness_connection
    ):
        self.profile.settings.set_value(
            "plugin_config",
            {"did-webvh": {"witness": True, "server_url": SERVER_URL}},
        )
        await self.controller.auto_witness_setup()
        assert not mock_get_active_witness_connection.called

    async def test_auto_witness_setup_as_controller_no_server_url(self):
        self.profile.settings.set_value(
            "plugin_config",
            {"did-webvh": {"witness": False}},
        )
        with self.assertRaises(ConfigurationError):
            await self.controller.auto_witness_setup()

    async def test_auto_witness_setup_as_controller_with_previous_connection(self):
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "witness": False,
                    "server_url": SERVER_URL,
                }
            },
        )
        async with self.profile.session() as session:
            record = ConnRecord(
                alias=f"{SERVER_URL}@Witness",
                state="active",
            )
            await record.save(session)
        await self.controller.auto_witness_setup()

    async def test_auto_witness_setup_as_controller_no_witness_invitation(self):
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "witness": False,
                    "server_url": SERVER_URL,
                }
            },
        )
        await self.controller.auto_witness_setup()

    @mock.patch.object(OutOfBandManager, "receive_invitation")
    @mock.patch.object(asyncio, "sleep")
    async def test_auto_witness_setup_as_controller_no_active_connection(self, *_):
        self.profile.settings.set_value("plugin_config.did-webvh.witness", False)
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "witness": False,
                    "server_url": SERVER_URL,
                    "witness_invitation": "http://witness:9050?oob=eyJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL291dC1vZi1iYW5kLzEuMS9pbnZpdGF0aW9uIiwgIkBpZCI6ICIwZDkwMGVjMC0wYzE3LTRmMTYtOTg1ZC1mYzU5MzVlYThjYTkiLCAibGFiZWwiOiAidGR3LWVuZG9yc2VyIiwgImhhbmRzaGFrZV9wcm90b2NvbHMiOiBbImh0dHBzOi8vZGlkY29tbS5vcmcvZGlkZXhjaGFuZ2UvMS4wIl0sICJzZXJ2aWNlcyI6IFt7ImlkIjogIiNpbmxpbmUiLCAidHlwZSI6ICJkaWQtY29tbXVuaWNhdGlvbiIsICJyZWNpcGllbnRLZXlzIjogWyJkaWQ6a2V5Ono2TWt0bXJUQURBWWRlc2Ftb3F1ZVV4NHNWM0g1Mms5b2ZoQXZRZVFaUG9vdTE3ZSN6Nk1rdG1yVEFEQVlkZXNhbW9xdWVVeDRzVjNINTJrOW9maEF2UWVRWlBvb3UxN2UiXSwgInNlcnZpY2VFbmRwb2ludCI6ICJodHRwOi8vbG9jYWxob3N0OjkwNTAifV19",
                }
            },
        )
        self.profile.context.injector.bind_instance(
            RouteManager, mock.AsyncMock(RouteManager, autospec=True)
        )
        await self.controller.auto_witness_setup()

    @mock.patch.object(OutOfBandManager, "receive_invitation")
    async def test_auto_witness_setup_as_controller_conn_becomes_active(self, *_):
        self.profile.settings.set_value("plugin_config.did-webvh.witness", False)
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "witness": False,
                    "server_url": SERVER_URL,
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
                    alias=f"{SERVER_URL}@Witness",
                    state="active",
                )
                await record.save(session)

        asyncio.create_task(_create_connection())
        await self.controller.auto_witness_setup()
