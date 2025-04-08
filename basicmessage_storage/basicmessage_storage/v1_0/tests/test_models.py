from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

from acapy_agent.utils.testing import create_test_profile

from ..models import BasicMessageRecord

_id = "mytestid"


class TestBasicMessageRecord(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.profile = await create_test_profile()

    async def test_init_creates_record_with_default_parameters(self):
        rec = BasicMessageRecord(record_id=_id)

        assert rec.record_id == _id
        assert rec._id == _id
        assert rec.state == BasicMessageRecord.STATE_SENT

    async def test_record_value_property_returns_set_attributes(self):
        _locale = "mylocale"
        _content = "mycontent"
        _sent_time = "mysenttime"

        rec = BasicMessageRecord(
            record_id=_id, locale=_locale, content=_content, sent_time=_sent_time
        )

        assert all(
            x in rec.record_value.values()
            for x in [_locale, _content, _sent_time, BasicMessageRecord.STATE_SENT]
        )

    @patch.object(BasicMessageRecord, "retrieve_by_tag_filter")
    async def test_retrieve_by_message_id_calls_retrieve_by_tag_filter_with_correct_args(
        self, mock_retrieve
    ):
        _message_id = "messageid"
        mock_retrieve.return_value = BasicMessageRecord(record_id=_id)

        rec = await BasicMessageRecord.retrieve_by_message_id(
            self.profile.session, _message_id
        )
        args = mock_retrieve.call_args.args
        expected_args = {"message_id": _message_id}

        assert mock_retrieve.called
        assert rec._id == _id
        assert mock_retrieve
        assert expected_args in args

    async def test_record_tags_returns_set_attributes(self):
        _connection_id = "myconnectionid"
        _message_id = "mymessageid"

        rec = BasicMessageRecord(
            record_id=_id, connection_id=_connection_id, message_id=_message_id
        )

        assert all(x in rec.record_tags.values() for x in [_connection_id, _message_id])
