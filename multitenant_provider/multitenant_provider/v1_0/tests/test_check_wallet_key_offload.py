"""Real-bcrypt tests for the wallet-key check (no mocks of bcrypt)."""

import asyncio
import time
from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock

import bcrypt

from ..manager import MulittokenHandler, _bcrypt_encode
from ..models import WalletTokenRecord


def record(key: str, rounds: int = 12, prefix: bytes = b"2b") -> WalletTokenRecord:
    """A token record exactly as find_or_create_wallet_token_record stores it."""
    salt = bcrypt.gensalt(rounds=rounds, prefix=prefix)
    return WalletTokenRecord(
        wallet_id="wallet-id",
        wallet_key_salt=salt.decode("utf-8"),
        wallet_key_hash=bcrypt.hashpw(_bcrypt_encode(key), salt).decode("utf-8"),
    )


class TestCheckWalletKey(IsolatedAsyncioTestCase):
    def setUp(self):
        self.handler = MulittokenHandler(MagicMock())

    async def test_correct_key_accepted(self):
        rec = record("correct-key", rounds=4)
        assert self.handler.check_wallet_key(rec, "correct-key") is True
        assert await self.handler.check_wallet_key_async(rec, "correct-key") is True

    async def test_incorrect_keys_rejected(self):
        rec = record("correct-key", rounds=4)
        for wrong in ("wrong-key", "correct-ke", "correct-key ", "CORRECT-KEY", "x"):
            assert self.handler.check_wallet_key(rec, wrong) is False, wrong
            assert await self.handler.check_wallet_key_async(rec, wrong) is False, wrong

    async def test_existing_record_formats_still_verify(self):
        # Records created by earlier versions: $2b$12$ (current default) and $2a$.
        for rounds, prefix in ((12, b"2b"), (10, b"2a")):
            rec = record("legacy-key", rounds=rounds, prefix=prefix)
            assert await self.handler.check_wallet_key_async(rec, "legacy-key") is True
            assert await self.handler.check_wallet_key_async(rec, "other") is False

    async def test_keys_longer_than_bcrypt_limit_still_verify(self):
        # bcrypt 5 rejects inputs over 72 bytes; the check must keep encoding
        # keys the way the stored hash was made.
        long_key = "k" * 100
        rec = record(long_key, rounds=4)
        assert await self.handler.check_wallet_key_async(rec, long_key) is True
        assert await self.handler.check_wallet_key_async(rec, "k" * 71) is False

    async def test_check_does_not_block_event_loop(self):
        # A ticker on the loop must keep running while a cost-12 check runs.
        rec = record("k", rounds=12)
        lags = []

        async def ticker():
            while True:
                t = time.perf_counter()
                await asyncio.sleep(0.01)
                lags.append(time.perf_counter() - t - 0.01)

        tick = asyncio.create_task(ticker())
        start = time.perf_counter()
        assert await self.handler.check_wallet_key_async(rec, "k") is True
        took = time.perf_counter() - start
        tick.cancel()
        assert took > 0.05  # the check really ran bcrypt
        assert max(lags) < 0.1, (
            f"event loop stalled {max(lags):.3f}s during a {took:.3f}s check"
        )
        assert len(lags) >= int(took / 0.02)

    async def test_concurrent_checks_run_in_parallel_and_stay_correct(self):
        recs = [record(f"key-{i}", rounds=12) for i in range(4)]
        t = time.perf_counter()
        self.handler.check_wallet_key(recs[0], "key-0")
        single = time.perf_counter() - t

        start = time.perf_counter()
        results = await asyncio.gather(
            *[
                self.handler.check_wallet_key_async(r, f"key-{i}")
                for i, r in enumerate(recs)
            ],
            *[self.handler.check_wallet_key_async(r, "wrong") for r in recs],
        )
        took = time.perf_counter() - start
        assert results == [True] * 4 + [False] * 4
        # 8 checks: serialized would take ~8x a single check.
        assert took < 4 * single, (
            f"8 concurrent checks {took:.2f}s vs single {single:.2f}s"
        )
