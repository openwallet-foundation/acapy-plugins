from typing import Optional
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch

import bcrypt
import jwt
from acapy_agent.multitenant.error import WalletKeyMissingError
from acapy_agent.storage.error import StorageError
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.models.wallet_record import WalletRecord

from multitenant_provider.v1_0.config import (
    MultitenantProviderConfig,
    TokenExpiryConfig,
)

from ..config import ManagerConfig
from ..manager import (
    BasicMultitokenMultitenantManager,
    MulittokenHandler,
    WalletKeyMismatchError,
)
from ..models import WalletTokenRecord


class MockInjectMultitenantProviderConfig:
    def __init__(self, always_check_key: Optional[bool] = False) -> None:
        self.inject = lambda _: MultitenantProviderConfig.default()

    def inject(_):
        return MultitenantProviderConfig(
            manager=ManagerConfig(always_check_provided_wallet_key=False),
            token_expiry=TokenExpiryConfig(),
        )


class MockGetProfile:
    def __init__(self, always_check_key: Optional[bool] = False) -> None:
        self.context = MockInjectMultitenantProviderConfig(always_check_key)
        self.settings = {"multitenant.jwt_secret": "secret"}

    context = MockInjectMultitenantProviderConfig(False)
    settings = {"multitenant.jwt_secret": "secret"}


class MockWalletRecordRequiresKey:
    def __init__(self, requires_key: bool) -> None:
        self.requires_external_key = requires_key

    wallet_id = "test-wallet-id"


class TestMulittokenHandler(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.session_inject = {}
        self.profile = await create_test_profile()
        self.manager = BasicMultitokenMultitenantManager(self.profile)
        self.get_profile = lambda: self.profile
        self.context = MagicMock()

    async def test_multi_token_handler_constructor(self):
        multi_token_handler = MulittokenHandler(self.manager)
        assert multi_token_handler.manager is not None
        assert multi_token_handler.logger is not None

    @patch.object(
        WalletTokenRecord,
        "query_by_wallet_id",
        return_value="test-wallet",
    )
    async def test_find_or_create_wallet_token_record_returns_wallet_token_record_when_it_exists(
        self, _
    ):
        multi_token_handler = MulittokenHandler(self.manager)
        response = await multi_token_handler.find_or_create_wallet_token_record(
            "wallet-id", "wallet-key"
        )

        assert response == "test-wallet"

    @patch.object(WalletTokenRecord, "save")
    @patch.object(
        WalletTokenRecord,
        "query_by_wallet_id",
        return_value="test-wallet",
        side_effect=StorageError("test"),
    )
    @patch.object(
        WalletRecord,
        "retrieve_by_id",
        return_value=WalletRecord(
            wallet_id="wallet-id-test", settings={"type": "in_memory"}
        ),
    )
    async def test_find_or_create_wallet_token_record_returns_wallet_token_record_when_it_does_not_exists(
        self, mock_wallet_retrieve, mock_wallet_token_query, mock_save
    ):
        multi_token_handler = MulittokenHandler(self.manager)
        response = await multi_token_handler.find_or_create_wallet_token_record(
            "wallet-id", "wallet-key"
        )

        assert mock_wallet_retrieve.called
        assert mock_wallet_token_query.called
        assert mock_save.called
        assert isinstance(response, WalletTokenRecord)

    @patch.object(
        bcrypt,
        "checkpw",
        side_effect=[True, True, True, False, False, True, False, False],
    )
    async def test_check_wallet_key(self, mock_check):
        multi_token_handler = MulittokenHandler(self.manager)
        wallet_token_record = WalletTokenRecord(
            wallet_token_id="test-token-id",
            wallet_key_salt="$2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa",
            wallet_key_hash="$2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa",
        )
        result = multi_token_handler.check_wallet_key(
            wallet_token_record, wallet_key="wallet-key"
        )
        assert result is True
        assert mock_check.call_count == 2

        result = multi_token_handler.check_wallet_key(
            wallet_token_record, wallet_key="wallet-key"
        )
        assert result is False
        assert mock_check.call_count == 4

        result = multi_token_handler.check_wallet_key(
            wallet_token_record, wallet_key="wallet-key"
        )
        assert result is False
        assert mock_check.call_count == 6

        result = multi_token_handler.check_wallet_key(
            wallet_token_record, wallet_key="wallet-key"
        )
        assert result is False
        assert mock_check.call_count == 8

    @patch.object(
        MulittokenHandler,
        "find_or_create_wallet_token_record",
        return_value=WalletRecord(wallet_id="wallet-id"),
    )
    async def test_create_wallet_returns_record_on_success(self, mock_find_record):
        self.manager._super_create_wallet = AsyncMock()
        self.manager._super_create_wallet.return_value = WalletRecord(
            wallet_id="wallet-id"
        )
        multi_token_handler = MulittokenHandler(self.manager)
        wallet_record = await multi_token_handler.create_wallet(
            settings={"wallet.key": "wallet-key"}, key_management_mode="managed"
        )
        assert mock_find_record.called
        assert isinstance(wallet_record, WalletRecord)

    @patch.object(
        MulittokenHandler,
        "find_or_create_wallet_token_record",
        return_value=WalletTokenRecord(wallet_id="wallet-id"),
    )
    async def test_create_wallet_raises_exception_when_create_fails(
        self, mock_find_record
    ):
        self.manager._super_create_wallet = AsyncMock()
        self.manager._super_create_wallet.side_effect = Exception("test")

        multi_token_handler = MulittokenHandler(self.manager)
        with self.assertRaises(Exception):
            await multi_token_handler.create_wallet(
                settings={"wallet.key": "wallet-key"}, key_management_mode="managed"
            )
            assert mock_find_record.called is False

    @patch.object(
        MulittokenHandler,
        "find_or_create_wallet_token_record",
        return_value=WalletTokenRecord(wallet_id="wallet-id"),
        side_effect=Exception,
    )
    async def test_create_wallet_raises_exception_when_create_token_fails(self, _):
        self.manager._super_create_wallet = AsyncMock()
        self.manager._super_create_wallet.return_value = WalletRecord(
            wallet_id="wallet-id"
        )

        multi_token_handler = MulittokenHandler(self.manager)
        with self.assertRaises(Exception):
            await multi_token_handler.create_wallet(
                settings={"wallet.key": "wallet-key"}, key_management_mode="managed"
            )

    @patch.object(
        MulittokenHandler,
        "find_or_create_wallet_token_record",
        return_value=WalletTokenRecord(
            wallet_id="wallet-id",
            wallet_key_salt=MagicMock(
                encode=MagicMock(
                    return_value=bytes(
                        "$2a$04$LTpKKGs3P/oR7/7LMqxySukW3IYKZqSarX.b/cXzcSdduIV4rYoDC",
                        "utf-8",
                    )
                )
            ),
            wallet_key_hash=MagicMock(encode=MagicMock(return_value="test-password")),
        ),
    )
    @patch.object(
        WalletRecord,
        "save",
        return_value=WalletRecord(wallet_id="wallet-id-test"),
    )
    @patch.object(
        MulittokenHandler,
        "get_profile",
    )
    @patch.object(
        WalletTokenRecord,
        "save",
        return_value=WalletTokenRecord(wallet_id="wallet-id-test"),
    )
    @patch.object(
        bcrypt,
        "checkpw",
        return_value=True,
    )
    async def test_create_auth_token(
        self, mock_save_record, mock_save, mock_token_handler, *_
    ):
        secret_profile = await create_test_profile(
            settings={"multitenant.jwt_secret": "secret"}
        )
        secret_profile.context.injector.bind_instance(
            MultitenantProviderConfig,
            MultitenantProviderConfig.default(),
        )
        mock_token_handler.return_value = secret_profile

        wallet_record = WalletRecord(
            jwt_iat="test-jwt-iat",
            wallet_id="wallet-id",
            key_management_mode="managed",
            settings={"wallet.key": "wallet-key"},
        )
        multi_token_handler = MulittokenHandler(self.manager)
        token = await multi_token_handler.create_auth_token(
            wallet_record, wallet_key="wallet-key"
        )
        assert mock_save_record.called
        assert mock_save.called
        assert token is not None

    @patch.object(
        MulittokenHandler,
        "find_or_create_wallet_token_record",
        return_value=WalletTokenRecord(
            wallet_id="wallet-id",
        ),
    )
    @patch.object(
        MulittokenHandler,
        "get_profile",
    )
    async def test_create_auth_token_requires_key_without_key(
        self, mock_token_handler, _
    ):
        secret_profile = await create_test_profile(
            settings={"multitenant.jwt_secret": "secret"}
        )
        secret_profile.context.injector.bind_instance(
            MultitenantProviderConfig,
            MultitenantProviderConfig.default(),
        )
        mock_token_handler.return_value = secret_profile
        wallet_record = MockWalletRecordRequiresKey(True)
        multi_token_handler = MulittokenHandler(self.manager)
        with self.assertRaises(WalletKeyMissingError):
            await multi_token_handler.create_auth_token(wallet_record)

    @patch.object(
        MulittokenHandler,
        "find_or_create_wallet_token_record",
        return_value=WalletTokenRecord(
            wallet_id="wallet-id",
        ),
    )
    @patch.object(
        MulittokenHandler,
        "find_or_create_wallet_token_record",
        return_value=WalletTokenRecord(
            wallet_id="wallet-id",
        ),
    )
    @patch.object(MulittokenHandler, "check_wallet_key", return_value=False)
    @patch.object(
        MulittokenHandler,
        "get_profile",
    )
    async def test_create_auth_token_always_check_key_mismatch(
        self, mock_token_handler, *_
    ):
        secret_profile = await create_test_profile(
            settings={"multitenant.jwt_secret": "secret"}
        )
        secret_profile.context.injector.bind_instance(
            MultitenantProviderConfig,
            MultitenantProviderConfig.default(),
        )
        mock_token_handler.return_value = secret_profile
        wallet_record = WalletRecord(
            jwt_iat="test-jwt-iat",
            wallet_id="wallet-id",
            key_management_mode="unmanaged",
            settings={"wallet.key": "wallet-key"},
        )
        multi_token_handler = MulittokenHandler(self.manager)

        with self.assertRaises(WalletKeyMismatchError):
            await multi_token_handler.create_auth_token(
                wallet_record, wallet_key="wallet-key"
            )

    @patch.object(MulittokenHandler, "check_wallet_key", return_value=True)
    @patch.object(
        jwt,
        "decode",
        return_value={
            "wallet_id": "test-wallet-id",
            "wallet_key": "test-wallet-key",
            "iat": "test-iat",
        },
    )
    @patch.object(
        MulittokenHandler,
        "get_profile",
    )
    @patch.object(
        WalletRecord,
        "retrieve_by_id",
        return_value=WalletRecord(
            wallet_id="wallet-id-test", settings={"type": "in_memory"}
        ),
    )
    @patch.object(
        WalletTokenRecord,
        "query_by_wallet_id",
        return_value=WalletTokenRecord(
            wallet_id="wallet-id-test", issued_at_claims=["test-iat"]
        ),
    )
    async def test_get_profile_for_token(
        self, get_wallet_token, get_wallet, multitoken_manager, *_
    ):
        secret_profile = await create_test_profile(
            settings={"multitenant.jwt_secret": "jwt-secret"}
        )
        profile = await create_test_profile()
        multitoken_manager.side_effect = [secret_profile, profile]
        self.manager.get_wallet_profile = AsyncMock()
        multi_token_handler = MulittokenHandler(self.manager)
        self.manager.get_wallet_profile.return_value = "profile"
        profile = await multi_token_handler.get_profile_for_token(
            self.context,
            "test-token",
        )
        assert profile is not None
        assert get_wallet_token.called
        assert get_wallet.called

    @patch.object(MulittokenHandler, "check_wallet_key", return_value=True)
    @patch.object(
        jwt,
        "decode",
        side_effect=[
            jwt.exceptions.ExpiredSignatureError,
            {"wallet_id": "test-wallet-id", "iat": "test-iat"},
        ],
    )
    @patch.object(
        WalletTokenRecord,
        "query_by_wallet_id",
        return_value=MagicMock(WalletTokenRecord),
    )
    @patch.object(
        MulittokenHandler,
        "get_profile",
    )
    async def test_get_profile_for_token_expired_signature(self, multitoken_manager, *_):
        secret_profile = await create_test_profile(
            settings={"multitenant.jwt_secret": "jwt-secret"}
        )
        profile = await create_test_profile()
        multitoken_manager.side_effect = [secret_profile, profile]
        self.manager.get_wallet_profile = AsyncMock()
        multi_token_handler = MulittokenHandler(self.manager)
        self.manager.get_wallet_profile.return_value = "profile"
        with self.assertRaises(jwt.exceptions.ExpiredSignatureError):
            await multi_token_handler.get_profile_for_token(
                self.context,
                "test-token",
            )
