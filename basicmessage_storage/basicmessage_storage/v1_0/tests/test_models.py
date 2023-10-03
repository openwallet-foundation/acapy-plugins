from asynctest import TestCase as AsyncTestCase

from ..models import BasicMessageRecord


class TestBasicMessageRecord(AsyncTestCase):
    async def test_init(self):
        """Test initializing a record."""
        _id = "mytestid"
        rec = BasicMessageRecord(record_id=_id)

        assert rec.record_id == _id
        assert rec._id == _id
        assert rec.state == BasicMessageRecord.STATE_SENT
