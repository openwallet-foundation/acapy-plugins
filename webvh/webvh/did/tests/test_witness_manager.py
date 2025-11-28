from unittest import IsolatedAsyncioTestCase

from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.protocols.coordinate_mediation.v1_0.route_manager import RouteManager
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.wallet.keys.manager import MultikeyManager

from ..controller import ControllerManager
from ..witness import WitnessManager
from ..connection import WebVHConnectionManager
from ...config.config import get_plugin_config
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
            {"webvh": {"server_url": "https://example.com"}},
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
        assert self.witness.key_alias

    # Tests for setup() method removed - connection setup now happens in controller.configure()

    async def test_witness_auto_setup_skips_when_not_configured(self):
        self.profile.settings.set_value(
            "plugin_config",
            {
                "webvh": {
                    "witness": False,
                    "server_url": SERVER_URL,
                }
            },
        )
        await self.witness.configure()
        config = await get_plugin_config(self.profile)
        assert "witnesses" not in config

    async def test_witness_auto_setup_creates_key_and_updates_config(self):
        profile = await create_test_profile(
            {
                "wallet.type": "askar-anoncreds",
                "default_label": "TestWitness",
                "default_endpoint": "https://example.com",
            }
        )
        profile.settings.set_value(
            "plugin_config",
            {
                "webvh": {
                    "witness": True,
                    "server_url": SERVER_URL,
                }
            },
        )
        profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        profile.context.injector.bind_instance(
            RouteManager, mock.AsyncMock(RouteManager, autospec=True)
        )
        witness = WitnessManager(profile)
        with mock.patch.object(
            witness.witness_connection,
            "create_witness_invitation",
            new=mock.AsyncMock(return_value={"invitation_url": "https://example.com"}),
        ):
            await witness.configure()

        config = await get_plugin_config(profile)
        assert config.get("witnesses")
        assert len(config["witnesses"]) == 1
        # Ensure the witness key exists and can be retrieved
        assert await witness.key_chain.get_key(witness.key_alias)

    @mock.patch.object(WebVHConnectionManager, "create_witness_invitation")
    async def test_witness_configure_delegates_to_controller(
        self, mock_create_invitation
    ):
        """Test that witness.configure() works independently (it doesn't delegate to controller)."""
        # Mock the invitation creation
        mock_create_invitation.return_value = {
            "invitation_url": "https://example.com?oob=test123"
        }

        options = {"server_url": SERVER_URL, "auto_attest": True, "witness": True}
        # Witness.configure() doesn't delegate to ControllerManager.configure()
        # It handles witness configuration independently
        result = await self.witness.configure(options)
        assert result.get("witness_id") is not None
        assert result.get("witnesses") is not None
