from unittest import IsolatedAsyncioTestCase, mock

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.protocols.coordinate_mediation.v1_0.route_manager import RouteManager
from acapy_agent.protocols.out_of_band.v1_0.manager import OutOfBandManager
from acapy_agent.utils.testing import create_test_profile
from aiohttp.web_response import Response

from webvh.routes import attest_log_entry, configure, create, witness_get_pending


class TestWebvhRoutes(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile(
            settings={
                "wallet.type": "askar-anoncreds",
                "admin.admin_api_key": "secret-key",
            }
        )
        self.context = AdminRequestContext.test_context({}, self.profile)
        self.request_dict = {
            "context": self.context,
        }

    async def test_create(self):
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={},
            json=mock.AsyncMock(
                return_value={
                    "options": {
                        "namespace": "prod",
                        "identifier": "1234",
                        "parameters": {
                            "prerotation": False,
                            "portable": False,
                        },
                    },
                }
            ),
            __getitem__=lambda _, k: self.request_dict[k],
            headers={"x-api-key": "secret-key"},
        )

        await create(self.request)

    async def test_configure_witness(self):
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={},
            json=mock.AsyncMock(
                return_value={
                    "server_url": "id.test-suite.app",
                    "witness": True,
                    "auto_attest": True,
                }
            ),
            __getitem__=lambda _, k: self.request_dict[k],
            headers={"x-api-key": "secret-key"},
        )

        result = await configure(self.request)
        assert isinstance(result, Response)

    async def test_get_pending(self):
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
            headers={"x-api-key": "secret-key"},
        )

        result = await witness_get_pending(self.request)
        assert isinstance(result, Response)

    async def test_attest(self):
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={
                "entry_id": "1234",
            },
            __getitem__=lambda _, k: self.request_dict[k],
            headers={"x-api-key": "secret-key"},
        )

        result = await attest_log_entry(self.request)
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
                    "server_url": "id.test-suite.app",
                    "witness": False,
                    "witness_invitation": "http://witness/invite",
                }
            ),
            __getitem__=lambda _, k: self.request_dict[k],
            headers={"x-api-key": "secret-key"},
        )

        result = await configure(self.request)
        assert isinstance(result, Response)
