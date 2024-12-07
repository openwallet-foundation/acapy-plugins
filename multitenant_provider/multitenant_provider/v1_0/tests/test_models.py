from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

from acapy_agent.storage.error import StorageDuplicateError, StorageNotFoundError
from acapy_agent.utils.testing import create_test_profile

from ..models import WalletTokenRecord


class TestModels(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.profile = await create_test_profile()

    @patch.object(
        WalletTokenRecord,
        "query",
        return_value=["test-wallet"],
    )
    async def test_query_by_wallet_id_returns_one_record(self, mock_query):
        wallet_token_record = WalletTokenRecord()
        found_token_record = await wallet_token_record.query_by_wallet_id(
            session=self.profile.session, wallet_id="wallet-id"
        )
        assert mock_query.called
        assert found_token_record == "test-wallet"

    @patch.object(
        WalletTokenRecord,
        "query",
        return_value=["test-wallet-1", "test-wallet-2"],
    )
    async def test_query_by_wallet_id_raises_duplicate_error_when_multiple_records(
        self, mock_query
    ):
        wallet_token_record = WalletTokenRecord()
        with self.assertRaises(StorageDuplicateError):
            await wallet_token_record.query_by_wallet_id(
                session=self.profile.session, wallet_id="wallet-id"
            )
            assert mock_query.called

    @patch.object(
        WalletTokenRecord,
        "query",
        return_value=[],
    )
    async def test_query_by_wallet_id_raises_not_found_error_when_finds_no_records(
        self, mock_query
    ):
        wallet_token_record = WalletTokenRecord()
        with self.assertRaises(StorageNotFoundError):
            await wallet_token_record.query_by_wallet_id(
                session=self.profile.session, wallet_id="wallet-id"
            )
            assert mock_query.called
