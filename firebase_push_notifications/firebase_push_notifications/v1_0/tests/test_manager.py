import logging
import os
from datetime import timedelta
from unittest import IsolatedAsyncioTestCase
from unittest.mock import Mock, patch

import pytest
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.messaging.util import datetime_now, datetime_to_str
from acapy_agent.storage.base import StorageNotFoundError

from .. import manager as test_module
from ..constants import MAX_SEND_RATE_MINUTES
from ..models import FirebaseConnectionRecord

test_logger = logging.getLogger("v1_0.manager")


@pytest.fixture(autouse=True)
def mock_env_vars():
    with patch.dict(
        os.environ,
        {
            "FIREBASE_PROJECT_ID": "test-project-id",
            "FIREBASE_SERVICE_ACCOUNT": '{"type":"service_account","project_id":"test-project-id","private_key_id":"private-key-id","private_key":"private-key","client_email":"test@email.com","client_id":"101716881117602654718","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url":"https://www.googleapis.com/robot/v1/metadata/x509/cret-url.iam.gserviceaccount.com","universe_domain":"googleapis.com"}',
        },
    ):
        yield


@pytest.fixture(autouse=True)
def mock_logger():
    with patch.object(
        test_module, "_get_access_token", return_value="access-token"
    ) as mock_get_access_token:
        yield mock_get_access_token


class TestManager(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile()
        self.context = self.profile.context
        self.test_conn_id = "connection-id"

    @patch("requests.post")
    @patch.object(FirebaseConnectionRecord, "save")
    @patch.object(FirebaseConnectionRecord, "retrieve_by_connection_id")
    async def test_send_message_should_retrieve_send_push_and_save_for_valid_connection_with_no_last_sent_time(
        self, mock_retrieve, mock_save, mock_post
    ):
        mock_retrieve.return_value = FirebaseConnectionRecord(
            connection_id=self.test_conn_id, sent_time=None, device_token="device-token"
        )
        mock_post.return_value = Mock(status_code=200)
        await test_module.send_message(self.profile, self.test_conn_id)

        assert mock_retrieve.await_count == 1
        assert mock_post.called
        assert mock_save.await_count == 1

    @patch("requests.post")
    @patch.object(FirebaseConnectionRecord, "save")
    @patch.object(FirebaseConnectionRecord, "retrieve_by_connection_id")
    async def test_send_message_should_do_nothing_when_retrieved_device_token_is_blank(
        self, mock_retrieve, mock_save, mock_post
    ):
        mock_retrieve.return_value = FirebaseConnectionRecord(
            connection_id=self.test_conn_id, sent_time=None, device_token=""
        )
        mock_post.return_value = Mock(status_code=200)
        await test_module.send_message(self.profile, self.test_conn_id)

        assert mock_retrieve.await_count == 1
        assert not mock_post.called
        assert mock_save.await_count == 0

    @patch("requests.post")
    @patch.object(FirebaseConnectionRecord, "save")
    @patch.object(FirebaseConnectionRecord, "retrieve_by_connection_id")
    async def test_send_message_should_do_nothing_for_second_message_less_than_configured_time(
        self, mock_retrieve, mock_save, mock_post
    ):
        mock_retrieve.return_value = FirebaseConnectionRecord(
            connection_id=self.test_conn_id,
            sent_time=datetime_to_str(
                datetime_now() - timedelta(minutes=MAX_SEND_RATE_MINUTES - 1)
            ),
            device_token="device-token",
        )
        mock_post.return_value = Mock(status_code=200)
        await test_module.send_message(self.profile, self.test_conn_id)

        assert mock_retrieve.await_count == 1
        assert not mock_post.called
        assert mock_save.await_count == 0

    @patch("requests.post")
    @patch.object(FirebaseConnectionRecord, "save")
    @patch.object(FirebaseConnectionRecord, "retrieve_by_connection_id")
    async def test_send_message_should_retrieve_send_push_and_save_for_valid_connection_with_sent_time_greater_than_configured_time(
        self, mock_retrieve, mock_save, mock_post
    ):
        mock_retrieve.return_value = FirebaseConnectionRecord(
            connection_id=self.test_conn_id,
            sent_time=datetime_to_str(
                datetime_now() - timedelta(minutes=MAX_SEND_RATE_MINUTES + 1)
            ),
            device_token="device-token",
        )
        mock_post.return_value = Mock(status_code=200)
        await test_module.send_message(self.profile, self.test_conn_id)

        assert mock_retrieve.await_count == 1
        assert mock_post.called
        assert mock_save.await_count == 1

    @patch("requests.post")
    @patch.object(FirebaseConnectionRecord, "save")
    @patch.object(FirebaseConnectionRecord, "retrieve_by_connection_id")
    async def test_send_message_should_not_update_record_with_sent_time_when_firebase_fails(
        self, mock_retrieve, mock_save, mock_post
    ):
        mock_retrieve.return_value = FirebaseConnectionRecord(
            connection_id=self.test_conn_id,
            sent_time=datetime_to_str(
                datetime_now() - timedelta(minutes=MAX_SEND_RATE_MINUTES + 1)
            ),
            device_token="device-token",
        )
        mock_post.return_value = Mock(status_code=400)
        await test_module.send_message(self.profile, self.test_conn_id)

        assert mock_retrieve.await_count == 1
        assert mock_post.called
        assert mock_save.await_count == 0

    @patch.object(FirebaseConnectionRecord, "retrieve_by_connection_id")
    @patch.object(test_logger, "debug")
    @patch("requests.post")
    async def test_send_message_should_log_debug_when_retrieve_raises_error(
        self, mock_post, mock_logger_debug, mock_retrieve
    ):
        mock_retrieve.side_effect = StorageNotFoundError("test")
        await test_module.send_message(self.profile, self.test_conn_id)

        assert mock_retrieve.await_count == 1
        assert mock_logger_debug.call_count == 0
        assert not mock_post.called

    async def test_save_device_token_should_save_new_record(self):
        await test_module.save_device_token(
            self.profile, "device-token", self.test_conn_id
        )

    @patch.object(
        FirebaseConnectionRecord,
        "query",
        return_value=[
            FirebaseConnectionRecord(
                device_token="test-token",
                record_id="test-record-id",
            )
        ],
    )
    async def test_save_device_token_should_update(self, mock_conn_query):
        await test_module.save_device_token(
            self.profile, "device-token", self.test_conn_id
        )
