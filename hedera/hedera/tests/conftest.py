import pytest

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.event_bus import EventBus, MockEventBus
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.resolver.did_resolver import DIDResolver

from unittest.mock import create_autospec


@pytest.fixture
async def profile():
    profile = await create_test_profile(
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
    profile.context.injector.bind_instance(KeyTypes, KeyTypes())
    profile.context.injector.bind_instance(EventBus, MockEventBus())
    profile.context.injector.bind_instance(DIDResolver, DIDResolver())
    yield profile


@pytest.fixture
async def session_inject():
    session_inject = {BaseWallet: create_autospec(BaseWallet)}
    yield session_inject


@pytest.fixture
async def context(profile, session_inject):
    context = AdminRequestContext.test_context(session_inject, profile)
    yield context
