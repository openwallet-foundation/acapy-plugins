import logging
from unittest.async_case import IsolatedAsyncioTestCase

import pytest
from acapy_agent.cache.base import BaseCache
from acapy_agent.cache.in_memory import InMemoryCache
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.key_type import KeyTypes

from ..manager import CheqdDIDManager


@pytest.mark.anoncreds
class TestCheqdDidManager(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        did_methods = DIDMethods()
        self.profile = await create_test_profile(
            settings={"wallet.type": "askar-anoncreds"},
        )
        self.profile.context.injector.bind_instance(DIDMethods, did_methods)
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.logger = logging.getLogger(__name__)
        self.profile.context.injector.bind_instance(BaseCache, InMemoryCache())

    async def test_create_did(self):
        response = await CheqdDIDManager(self.profile).create({})
        did = response.get("did")
        assert did.startswith("did:cheqd:testnet")
        self.logger.info(f"DID: {did}")
        assert response.get("verkey")
