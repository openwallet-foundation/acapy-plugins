from unittest import IsolatedAsyncioTestCase, mock

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.protocols.coordinate_mediation.v1_0.route_manager import RouteManager
from acapy_agent.protocols.out_of_band.v1_0.manager import OutOfBandManager
from acapy_agent.utils.testing import create_test_profile
from aiohttp.web_response import Response

from webvh.routes import (
    get_config,
    configure,
    create,
    on_startup_event,
)

TEST_SERVER_URL = "https://sandbox.bcvh.vonx.io"
TEST_WITNESS_INVITATION = {
    "@type": "https://didcomm.org/out-of-band/1.1/invitation",
    "@id": "fe469f3d-b288-4e3f-99ba-b631af98248b",
    "label": "Witness Service",
    "handshake_protocols": [
        "https://didcomm.org/didexchange/1.0",
        "https://didcomm.org/didexchange/1.1",
    ],
    "services": [
        {
            "id": "#inline",
            "type": "did-communication",
            "recipientKeys": [
                "did:key:z6MkmzPEig7GBQBeSRt7b2D55GTpzJ5ynyVgC5ifmS4X5HJK#z6MkmzPEig7GBQBeSRt7b2D55GTpzJ5ynyVgC5ifmS4X5HJK"
            ],
            "serviceEndpoint": "https://example.com",
        }
    ],
    "goal_code": "witness-service",
    "goal": "did:key:z6Mko6hFCJNZwfhCefDf1iEHwwM9FtENHDTmkT5BQyt9eYiQ",
}
TEST_WITNESS_INVITATION_URL = "https://example.com?oob=ew0KICAgICJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL291dC1vZi1iYW5kLzEuMS9pbnZpdGF0aW9uIiwNCiAgICAiQGlkIjogImZlNDY5ZjNkLWIyODgtNGUzZi05OWJhLWI2MzFhZjk4MjQ4YiIsDQogICAgImxhYmVsIjogIldpdG5lc3MgU2VydmljZSIsDQogICAgImhhbmRzaGFrZV9wcm90b2NvbHMiOiBbDQogICAgICAgICJodHRwczovL2RpZGNvbW0ub3JnL2RpZGV4Y2hhbmdlLzEuMCIsDQogICAgICAgICJodHRwczovL2RpZGNvbW0ub3JnL2RpZGV4Y2hhbmdlLzEuMSINCiAgICBdLA0KICAgICJzZXJ2aWNlcyI6IFsNCiAgICAgICAgew0KICAgICAgICAgICAgImlkIjogIiNpbmxpbmUiLA0KICAgICAgICAgICAgInR5cGUiOiAiZGlkLWNvbW11bmljYXRpb24iLA0KICAgICAgICAgICAgInJlY2lwaWVudEtleXMiOiBbDQogICAgICAgICAgICAgICAgImRpZDprZXk6ejZNa216UEVpZzdHQlFCZVNSdDdiMkQ1NUdUcHpKNXlueVZnQzVpZm1TNFg1SEpLI3o2TWttelBFaWc3R0JRQmVTUnQ3YjJENTVHVHB6SjV5bnlWZ0M1aWZtUzRYNUhKSyINCiAgICAgICAgICAgIF0sDQogICAgICAgICAgICAic2VydmljZUVuZHBvaW50IjogImh0dHBzOi8vZXhhbXBsZS5jb20iDQogICAgICAgIH0NCiAgICBdLA0KICAgICJnb2FsX2NvZGUiOiAid2l0bmVzcy1zZXJ2aWNlIiwNCiAgICAiZ29hbCI6ICJkaWQ6a2V5Ono2TWtvNmhGQ0pOWndmaENlZkRmMWlFSHd3TTlGdEVOSERUbWtUNUJReXQ5ZVlpUSINCn0"


class TestWebvhRoutes(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile(
            settings={
                "wallet.type": "askar-anoncreds",
                "admin.admin_insecure_mode": True,
            }
        )
        self.context = AdminRequestContext.test_context({}, self.profile)
        self.request_dict = {
            "context": self.context,
        }

    async def test_get_config(self):
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
        )
        await get_config(self.request)

    async def test_configure_witness(self):
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={},
            json=mock.AsyncMock(
                return_value={
                    "server_url": TEST_SERVER_URL,
                    "witness": True,
                    "auto_attest": True,
                    "auto_config": False,
                }
            ),
            __getitem__=lambda _, k: self.request_dict[k],
        )

        result = await configure(self.request)
        assert isinstance(result, Response)

    @mock.patch.object(OutOfBandManager, "receive_invitation")
    async def test_configure_controller(self, *_):
        self.profile.context.injector.bind_instance(
            RouteManager, mock.MagicMock(RouteManager, auto_spec=True)
        )
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={},
            json=mock.AsyncMock(
                return_value={
                    "server_url": TEST_SERVER_URL,
                    "witness": False,
                    "witness_invitation": TEST_WITNESS_INVITATION_URL,
                    "auto_config": True,
                }
            ),
            __getitem__=lambda _, k: self.request_dict[k],
        )

        result = await configure(self.request)
        assert isinstance(result, Response)

    async def test_create(self):
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={},
            json=mock.AsyncMock(
                return_value={
                    "options": {},
                }
            ),
            __getitem__=lambda _, k: self.request_dict[k],
        )

        await create(self.request)

    @mock.patch("webvh.routes.WitnessManager.configure", new_callable=mock.AsyncMock)
    @mock.patch("webvh.routes.ControllerManager.configure", new_callable=mock.AsyncMock)
    async def test_on_startup_event_skips_when_auto_setup_disabled(
        self, mock_controller_configure, mock_witness_auto
    ):
        self.profile.settings.set_value("multitenant.enabled", False)
        self.profile.settings.set_value(
            "plugin_config",
            {"webvh": {"server_url": TEST_SERVER_URL, "auto_config": False}},
        )
        await on_startup_event(self.profile, mock.MagicMock())
        assert mock_controller_configure.await_count == 0
        assert mock_witness_auto.await_count == 0

    @mock.patch("webvh.routes.WitnessManager.configure", new_callable=mock.AsyncMock)
    @mock.patch("webvh.routes.ControllerManager.configure", new_callable=mock.AsyncMock)
    async def test_on_startup_event_runs_controller_auto_setup(
        self, mock_controller_configure, mock_witness_auto
    ):
        self.profile.settings.set_value("multitenant.enabled", False)
        self.profile.settings.set_value(
            "plugin_config",
            {
                "webvh": {
                    "server_url": TEST_SERVER_URL,
                    "witness_id": TEST_WITNESS_INVITATION["goal"],
                    "auto_config": True,
                }
            },
        )
        await on_startup_event(self.profile, mock.MagicMock())
        mock_controller_configure.assert_awaited_once()
        assert mock_witness_auto.await_count == 0

    @mock.patch("webvh.routes.WitnessManager.configure", new_callable=mock.AsyncMock)
    @mock.patch("webvh.routes.ControllerManager.configure", new_callable=mock.AsyncMock)
    async def test_on_startup_event_runs_witness_auto_setup(
        self, mock_controller_configure, mock_witness_auto
    ):
        self.profile.settings.set_value("multitenant.enabled", False)
        self.profile.settings.set_value(
            "plugin_config",
            {
                "webvh": {
                    "server_url": TEST_SERVER_URL,
                    "witness": True,
                    "auto_config": True,
                }
            },
        )
        # Mock configure to return config with witness_id and invitation_url
        mock_witness_auto.return_value = {
            "witness_id": TEST_WITNESS_INVITATION["goal"],
            "invitation_url": "https://example.com/invitation",
        }
        await on_startup_event(self.profile, mock.MagicMock())
        assert mock_controller_configure.await_count == 0
        mock_witness_auto.assert_awaited_once()
