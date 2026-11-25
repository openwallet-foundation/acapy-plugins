"""Concurrent token requests for one wallet, against real storage and bcrypt."""

import asyncio
import itertools
from datetime import datetime, timedelta, timezone
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

import bcrypt
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.models.wallet_record import WalletRecord

from .. import manager as manager_module
from ..config import MultitenantProviderConfig
from ..manager import (
    BasicMultitokenMultitenantManager,
    MulittokenHandler,
    WalletKeyMismatchError,
)
from ..models import WalletTokenRecord

WALLET_KEY = "wallet-key"


class _Clock:
    """Stand-in for manager.datetime: each now() is one second later.

    JWT iat has one-second resolution; distinct seconds make every token's
    claim distinguishable, which is the case where claims used to be lost.
    """

    def __init__(self):
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self._ticks = (base + timedelta(seconds=n) for n in itertools.count())

    def now(self, tz=None):
        return next(self._ticks)


class TestConcurrentAuthTokens(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile(
            settings={"multitenant.jwt_secret": "secret"}
        )
        # default(): always_check_provided_wallet_key=True, as Traction ships it
        self.profile.context.injector.bind_instance(
            MultitenantProviderConfig, MultitenantProviderConfig.default()
        )
        self.handler = MulittokenHandler(BasicMultitokenMultitenantManager(self.profile))

        self.wallets = []
        async with self.profile.session() as session:
            for name in ("wallet-a", "wallet-b"):
                wallet = WalletRecord(
                    key_management_mode="managed",
                    settings={"wallet.name": name, "wallet.key": WALLET_KEY},
                )
                await wallet.save(session)
                salt = bcrypt.gensalt(rounds=4)
                await WalletTokenRecord(
                    wallet_id=wallet.wallet_id,
                    issued_at_claims=[],
                    wallet_key_salt=salt.decode("utf-8"),
                    wallet_key_hash=bcrypt.hashpw(
                        WALLET_KEY.encode("utf-8"), salt
                    ).decode("utf-8"),
                ).save(session)
                self.wallets.append(wallet)

    async def stored_claims(self, wallet_id):
        async with self.profile.session() as session:
            record = await WalletTokenRecord.query_by_wallet_id(session, wallet_id)
            return list(record.issued_at_claims)

    async def test_concurrent_tokens_for_one_wallet_all_stay_valid(self):
        wallet = self.wallets[0]
        with patch.object(manager_module, "datetime", _Clock()):
            tokens = await asyncio.gather(
                *[self.handler.create_auth_token(wallet, WALLET_KEY) for _ in range(4)]
            )
        iats = [
            manager_module.jwt.decode(t, "secret", algorithms=["HS256"])["iat"]
            for t in tokens
        ]
        assert len(set(iats)) == 4
        # every issued token's claim survived; none were overwritten
        assert sorted(await self.stored_claims(wallet.wallet_id)) == sorted(iats)

    async def test_concurrent_tokens_across_wallets_are_kept_per_wallet(self):
        with patch.object(manager_module, "datetime", _Clock()):
            tokens = await asyncio.gather(
                *[self.handler.create_auth_token(w, WALLET_KEY) for w in self.wallets * 2]
            )
        by_wallet = {w.wallet_id: [] for w in self.wallets}
        for t in tokens:
            body = manager_module.jwt.decode(t, "secret", algorithms=["HS256"])
            by_wallet[body["wallet_id"]].append(body["iat"])
        for wallet_id, iats in by_wallet.items():
            assert len(iats) == 2
            assert sorted(await self.stored_claims(wallet_id)) == sorted(iats)

    async def test_wrong_key_is_still_rejected_and_adds_no_claim(self):
        wallet = self.wallets[0]
        with self.assertRaises(WalletKeyMismatchError):
            await self.handler.create_auth_token(wallet, "wrong-key")
        assert await self.stored_claims(wallet.wallet_id) == []
