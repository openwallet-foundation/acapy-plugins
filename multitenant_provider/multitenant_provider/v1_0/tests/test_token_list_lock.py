"""Per-wallet lock around issued-claims list updates."""

import asyncio
import gc
from unittest import IsolatedAsyncioTestCase

from .. import manager


class TestTokenListLock(IsolatedAsyncioTestCase):
    async def test_same_wallet_shares_one_lock(self):
        a = manager._token_list_lock("wallet-a")
        assert manager._token_list_lock("wallet-a") is a
        assert manager._token_list_lock("wallet-b") is not a

    async def test_same_wallet_serializes_different_wallets_do_not(self):
        order = []

        async def critical(wallet_id, tag):
            async with manager._token_list_lock(wallet_id):
                order.append(f"{tag}+")
                await asyncio.sleep(0.05)
                order.append(f"{tag}-")

        # same wallet: never interleaved
        await asyncio.gather(critical("w1", "a"), critical("w1", "b"))
        assert order in (["a+", "a-", "b+", "b-"], ["b+", "b-", "a+", "a-"])

        # different wallets: both inside at once
        order.clear()
        await asyncio.gather(critical("w2", "c"), critical("w3", "d"))
        assert order.index("d+") < order.index("c-") or order.index("c+") < order.index(
            "d-"
        )
        assert order[:2] in (["c+", "d+"], ["d+", "c+"])

    async def test_unused_locks_are_released(self):
        manager._token_list_lock("wallet-temp")
        gc.collect()
        assert "wallet-temp" not in manager._token_list_locks
