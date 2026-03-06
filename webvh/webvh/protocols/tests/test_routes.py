import json
import uuid
from unittest import IsolatedAsyncioTestCase

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from aiohttp.web_response import Response

from . import (
    TEST_DOMAIN,
    TEST_SCID,
    TEST_LOG_ENTRY_RECORD,
    TEST_ATTESTED_RESOURCE_RECORD,
    TEST_RECORD_ID,
)
from ..log_entry.record import PendingLogEntryRecord
from ..attested_resource.record import PendingAttestedResourceRecord
from ..routes import (
    get_pending_witness_requests,
    approve_pending_witness_request,
    reject_pending_witness_request,
)
from ...config.config import set_config
from ...did.manager import ControllerManager


class TestProtocolRoutesLogEntry(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile(
            settings={
                "wallet.type": "askar-anoncreds",
                "admin.admin_insecure_mode": True,
            }
        )
        self.profile.settings.set_value(
            "plugin_config", {"webvh": {"server_url": f"https://{TEST_DOMAIN}"}}
        )
        self.context = AdminRequestContext.test_context({}, self.profile)
        self.request_dict = {
            "context": self.context,
        }
        self.record = PendingLogEntryRecord()

    async def test_get_pending_log_entries(self):
        await self.record.save_pending_record(
            self.profile, TEST_SCID, TEST_LOG_ENTRY_RECORD, TEST_RECORD_ID
        )
        self.request = mock.MagicMock(
            app={},
            match_info={"record_type": "log-entry"},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
        )

        response = await get_pending_witness_requests(self.request)
        assert isinstance(response, Response)

    @mock.patch("webvh.did.manager.is_witness", mock.AsyncMock(return_value=True))
    async def test_controller_request_visible_via_route(self):
        """Verify controller-saved request is retrievable via GET /requests."""
        await set_config(self.profile, {"server_url": f"https://{TEST_DOMAIN}"})
        controller = ControllerManager(self.profile)

        request_id = str(uuid.uuid4())
        await controller._request_witness_signature(
            request_id,
            log_entry=TEST_LOG_ENTRY_RECORD,
            scid=TEST_SCID,
        )

        self.request = mock.MagicMock(
            app={},
            match_info={"record_type": "log-entry"},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
        )
        response = await get_pending_witness_requests(self.request)

        assert isinstance(response, Response)
        assert response.status == 200
        body = json.loads(response.body) if response.body else {}
        results = body.get("results", [])
        assert any(r.get("record_id") == request_id for r in results)

        await self.record.remove_pending_record(self.profile, request_id)

    async def test_approve_pending_log_entry(self):
        await self.record.save_pending_record(
            self.profile, TEST_SCID, TEST_LOG_ENTRY_RECORD, TEST_RECORD_ID
        )
        self.request = mock.MagicMock(
            app={},
            match_info={"record_type": "log-entry", "record_id": TEST_RECORD_ID},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
        )
        response = await approve_pending_witness_request(self.request)
        assert isinstance(response, Response)

    async def test_reject_pending_log_entry(self):
        await self.record.save_pending_record(
            self.profile, TEST_SCID, TEST_LOG_ENTRY_RECORD, TEST_RECORD_ID
        )
        self.request = mock.MagicMock(
            app={},
            match_info={"record_type": "log-entry", "record_id": TEST_RECORD_ID},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
        )
        response = await reject_pending_witness_request(self.request)
        assert isinstance(response, Response)


class TestProtocolRoutesAttestedResource(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile(
            settings={
                "wallet.type": "askar-anoncreds",
                "admin.admin_insecure_mode": True,
            }
        )
        self.profile.settings.set_value(
            "plugin_config", {"webvh": {"server_url": f"https://{TEST_DOMAIN}"}}
        )
        self.context = AdminRequestContext.test_context({}, self.profile)
        self.request_dict = {
            "context": self.context,
        }
        self.record = PendingAttestedResourceRecord()

    async def test_get_pending_attested_resources(self):
        await self.record.save_pending_record(
            self.profile, TEST_SCID, TEST_ATTESTED_RESOURCE_RECORD, TEST_RECORD_ID
        )
        self.request = mock.MagicMock(
            app={},
            match_info={"record_type": "attested-resource"},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
        )

        response = await get_pending_witness_requests(self.request)
        assert isinstance(response, Response)

    async def test_approve_pending_attested_resource(self):
        await self.record.save_pending_record(
            self.profile, TEST_SCID, TEST_ATTESTED_RESOURCE_RECORD, TEST_RECORD_ID
        )
        self.request = mock.MagicMock(
            app={},
            match_info={"record_type": "attested-resource", "record_id": TEST_RECORD_ID},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
        )
        response = await approve_pending_witness_request(self.request)
        assert isinstance(response, Response)

    async def test_reject_pending_attested_resource(self):
        await self.record.save_pending_record(
            self.profile, TEST_SCID, TEST_ATTESTED_RESOURCE_RECORD, TEST_RECORD_ID
        )
        self.request = mock.MagicMock(
            app={},
            match_info={"record_type": "attested-resource", "record_id": TEST_RECORD_ID},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
        )
        response = await reject_pending_witness_request(self.request)
        assert isinstance(response, Response)
