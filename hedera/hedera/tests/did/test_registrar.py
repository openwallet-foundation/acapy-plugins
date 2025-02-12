import pytest

from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, Mock, create_autospec, patch

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.base import BaseWallet, KeyInfo
from acapy_agent.wallet.key_type import ED25519, KeyTypes

from hedera.did import HederaDIDRegistrar


class TestHederaDIDRegistrar(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.wallet = create_autospec(BaseWallet)
        self.session_inject = {BaseWallet: self.wallet}
        self.profile = await create_test_profile(
            settings={
                "admin.admin_api_key": "admin_api_key",
                "admin.admin_insecure_mode": False,
                "plugin_config": {
                    "hedera": {
                        "network": "testnet",
                        "operator_id": "0.0.1",
                        "operator_key": "31ACDD47830239324BA37D493F959A1585774DBC04DA0679C162B95151F6593C",
                    }
                },
            }
        )
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.context = AdminRequestContext.test_context(self.session_inject, self.profile)

    @patch("hedera.did.registrar.HederaDid")
    async def test_registers_did(self, mock_hedera_did):
        mock_did_info = {
            "did": "did:hedera:testnet:zEBxZtv3ttiDsySAYa6eNxorEYSnUk7WsKJBUfUjFQiLL_0.0.5244981",
            "verkey": "DCPsdMHmKoRv44epK3fNCQRUvk9ByPYeqgZnsU1fejuX",
            "key_type": "ed25519",
        }

        self.wallet._session = MagicMock(
            handle=AsyncMock(
                fetch_key=AsyncMock(
                    return_value=Mock(
                        key=Mock(
                            get_secret_bytes=Mock(
                                return_value=b"\xbcAQ\xb8\x91NZP\xb4\x99\xf6f\xb7\xff\xca\x7f\xffO\x9aC\xdb\xbf\xea\xed2\x83\xa0\xf2\xc1\xca\t]"
                            )
                        )
                    )
                ),
                insert=AsyncMock(return_value=None),
            )
        )

        self.wallet.create_key.return_value = KeyInfo(
            mock_did_info["verkey"], {}, ED25519
        )

        mock_hedera_did.return_value.register = AsyncMock(return_value={})
        mock_hedera_did.return_value.identifier = mock_did_info["did"]

        result = await HederaDIDRegistrar(self.context).register(
            mock_did_info["key_type"]
        )
        assert result == mock_did_info

    async def test_throws_on_missing_key_types(self):
        self.session_inject[KeyTypes] = None

        with pytest.raises(Exception, match="Failed to inject supported key types enum"):
            await HederaDIDRegistrar(self.context).register("Ed25519")

    async def test_throws_on_missing_wallet(self):
        self.session_inject[BaseWallet] = None

        with pytest.raises(Exception, match="Failed to inject wallet instance"):
            await HederaDIDRegistrar(self.context).register("Ed25519")
