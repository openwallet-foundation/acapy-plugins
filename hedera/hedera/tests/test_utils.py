from unittest.mock import AsyncMock, MagicMock, Mock

from acapy_agent.multitenant.base import BaseMultitenantManager
from acapy_agent.wallet.base import BaseWallet
from hedera.utils import get_encoded_private_key_for_did, inject_or_fail
import pytest


class TestUtils:
    class TestGetPrivateKeyFromDid:
        async def test_fail_no_key(self):
            did = "did:hedera:testnet:zEBxZtv3ttiDsySAYa6eNxorEYSnUk7WsKJBUfUjFQiLL_0.0.5244981"

            mock_empty_wallet = MagicMock(
                _session=MagicMock(
                    handle=MagicMock(fetch_key=AsyncMock(return_value=None))
                )
            )

            with pytest.raises(Exception, match="Could not fetch key"):
                await get_encoded_private_key_for_did(mock_empty_wallet, did)

        @pytest.mark.parametrize(
            "did, secret_bytes, expected_private_key",
            [
                (
                    "did:hedera:testnet:4ksE88fnB5ta7J5GPB4QEkLF7cKQDY5bqDqyiEucik6u_0.0.5244981",
                    b"\xc7\xb7\xb7\xc1.+\x13 \xe4e\xec\x80\x9b.g\x00N_\xfd(\xdf\xdao\x13\xec>\x95~\xccV\x95>",
                    "c7b7b7c12e2b1320e465ec809b2e67004e5ffd28dfda6f13ec3e957ecc56953e",
                ),
                (
                    "did:hedera:testnet:8F4WeYYM6gJJXkKd4Zad6hweLyvSigTX4nrraa2zWp5n_0.0.5244981",
                    b"C\x8c\xa5)\xe3f\x85\xbf\xca\xa82\xc8\x90^\x84\x9d\tv{\xe9=A>\xb2D.\xf9o\x15\x88fM",
                    "438ca529e36685bfcaa832c8905e849d09767be93d413eb2442ef96f1588664d",
                ),
            ],
        )
        async def test_success(self, did, secret_bytes, expected_private_key):
            mock_wallet = MagicMock(
                _session=MagicMock(
                    handle=MagicMock(
                        fetch_key=AsyncMock(
                            return_value=Mock(
                                key=Mock(get_secret_bytes=Mock(return_value=secret_bytes))
                            )
                        )
                    )
                )
            )

            encoded_private_key = await get_encoded_private_key_for_did(mock_wallet, did)

            assert encoded_private_key == expected_private_key

    @pytest.mark.parametrize(
        "base_class, exception_to_throw",
        [
            (BaseWallet, Exception),
            (BaseMultitenantManager, Exception),
        ],
    )
    class TestInjectOrFail:
        def test_fail(self, base_class, exception_to_throw):
            mock_session = MagicMock(inject_or=(MagicMock(return_value=None)))

            with pytest.raises(
                exception_to_throw, match=f"Could not inject class {base_class}"
            ):
                inject_or_fail(mock_session, base_class, exception_to_throw)
