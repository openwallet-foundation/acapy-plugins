from unittest import IsolatedAsyncioTestCase

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from aiohttp.web_response import Response

from . import TEST_DOMAIN, TEST_SCID, TEST_RECORD, TEST_RECORD_ID
from ..record import PendingLogEntryRecord
from ..routes import (
    get_pending_log_entries,
    approve_pending_log_entry,
    reject_pending_log_entry,
)


class TestLogEntryRoutes(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile(
            settings={
                "wallet.type": "askar-anoncreds",
                "admin.admin_insecure_mode": True,
            }
        )
        self.profile.settings.set_value(
            "plugin_config", {"did-webvh": {"server_url": f"https://{TEST_DOMAIN}"}}
        )
        self.context = AdminRequestContext.test_context({}, self.profile)
        self.request_dict = {
            "context": self.context,
        }
        self.record = PendingLogEntryRecord()

    async def test_get_pending_log_entries(self):
        await self.record.save_pending_record(
            self.profile, TEST_SCID, TEST_RECORD, TEST_RECORD_ID
        )
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
        )

        response = await get_pending_log_entries(self.request)
        assert isinstance(response, Response)

    async def test_approve_pending_log_entry(self):
        await self.record.save_pending_record(
            self.profile, TEST_SCID, TEST_RECORD, TEST_RECORD_ID
        )
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={"record_id": TEST_RECORD_ID},
            __getitem__=lambda _, k: self.request_dict[k],
        )
        response = await approve_pending_log_entry(self.request)
        assert isinstance(response, Response)

    async def test_reject_pending_log_entry(self):
        await self.record.save_pending_record(
            self.profile, TEST_SCID, TEST_RECORD, TEST_RECORD_ID
        )
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={"record_id": TEST_RECORD_ID},
            __getitem__=lambda _, k: self.request_dict[k],
        )
        response = await reject_pending_log_entry(self.request)
        assert isinstance(response, Response)
