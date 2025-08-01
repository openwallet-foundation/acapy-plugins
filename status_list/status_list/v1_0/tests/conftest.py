import pytest

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.config.plugin_settings import PLUGIN_CONFIG_KEY
from acapy_agent.config.settings import Settings
from acapy_agent.core.profile import Profile
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_method import DIDMethods, WEB
from acapy_agent.wallet.key_type import KeyTypes, ED25519
from acapy_agent.wallet.default_verification_key_strategy import (
    BaseVerificationKeyStrategy,
    DefaultVerificationKeyStrategy,
)

from ..models import StatusListDef, StatusListCred
from ..config import Config
from .. import status_handler


def pytest_collection_modifyitems(items):
    """test items come to first"""
    run_first = [
        "status_list.v1_0.tests.test_models",
        "status_list.v1_0.tests.controllers.test_status_list_cred",
        "status_list.v1_0.tests.controllers.test_status_list_pub",
        "status_list.v1_0.tests.controllers.test_status_list_shard",
        "status_list.v1_0.tests.controllers.test_status_list_def",
        "status_list.v1_0.tests.test_status_handler",
    ]
    modules = {item: item.module.__name__ for item in items}
    items[:] = sorted(
        items,
        key=lambda x: (
            run_first.index(modules[x]) if modules[x] in run_first else len(items)
        ),
    )


@pytest.fixture(scope="session")
def plugin_settings():
    yield {
        PLUGIN_CONFIG_KEY: {
            "status_list": {
                "list_size": "131072",
                "shard_size": "1024",
                "public_uri": "https://status.di.gov.on.ca/tenants/{tenant_id}/status/{list_number}",
                "file_path": "/tmp/bitstring/{tenant_id}/{list_number}",
            }
        }
    }


@pytest.fixture(scope="session")
def plugin_config(plugin_settings):
    yield Config.from_settings(Settings(plugin_settings))


@pytest.fixture(autouse=True)
def inject_config(monkeypatch, plugin_config):
    monkeypatch.setattr("status_list.v1_0.models.Config", plugin_config)


@pytest.fixture(scope="session")
async def profile(plugin_settings: dict):
    """Test Profile."""
    profile = await create_test_profile(
        {
            "admin.admin_insecure_mode": True,
            **plugin_settings,
        }
    )
    profile.context.injector.bind_instance(DIDMethods, DIDMethods())
    profile.context.injector.bind_instance(
        BaseVerificationKeyStrategy, DefaultVerificationKeyStrategy()
    )
    profile.context.injector.bind_instance(KeyTypes, KeyTypes())
    yield profile


@pytest.fixture(scope="session")
def context(profile: Profile):
    """Test AdminRequestContext."""
    yield AdminRequestContext(profile)


@pytest.fixture(scope="session", autouse=True)
async def init(context: AdminRequestContext):
    async with context.profile.session() as session:
        wallet = session.inject_or(BaseWallet)
        await wallet.create_local_did(
            method=WEB,
            key_type=ED25519,
            seed="testseed000000000000000000000001",
            did="did:web:dev.lab.di.gov.on.ca",
        )
    yield


@pytest.fixture(scope="session")
def status_list_def():
    yield StatusListDef(
        supported_cred_id="supported_cred_id",
        status_purpose="revocation",
        status_size=1,
        shard_size=1024,
        list_type="ietf",
        list_size=131072,
        list_number="0",
        next_list_number="0",
        issuer_did="did:web:dev.lab.di.gov.on.ca",
        verification_method="did:web:dev.lab.di.gov.on.ca#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
        id="definition_id",
        new_with_id=True,
    )


@pytest.fixture(scope="session")
def status_list_def_msg():
    yield StatusListDef(
        supported_cred_id="supported_cred_id",
        status_purpose="message",
        status_message=[
            {"status": "0x00", "message": "active"},
            {"status": "0x01", "message": "revoked"},
            {"status": "0x10", "message": "pending"},
            {"status": "0x11", "message": "suspended"},
        ],
        status_size=2,
        shard_size=6,
        list_size=16,
        list_number="0",
        next_list_number="0",
        issuer_did="did:web:dev.lab.di.gov.on.ca",
        verification_method="did:web:dev.lab.di.gov.on.ca#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
        id="definition_msg_id",
        new_with_id=True,
    )


@pytest.fixture(scope="session")
def status_list_cred():
    yield StatusListCred(
        definition_id="definition_id",
        credential_id="credential_id",
        list_number="0",
        list_index=57608,
        state="entry-assigned",
        id="credential_id",
        new_with_id=True,
    )


@pytest.fixture(scope="session")
async def seed_db(
    context: AdminRequestContext,
    status_list_def,
    status_list_def_msg,
    status_list_cred,
):
    async with context.profile.transaction() as txn:
        wallet_id = status_handler.get_wallet_id(context)

        # Create revocation status list
        list_number = await status_handler.assign_status_list_number(txn, wallet_id)
        status_list_def.next_list_number = list_number
        status_list_def.list_number = list_number
        status_list_def.add_list_number(list_number)
        await status_handler.create_next_status_list(txn, status_list_def)

        list_number = await status_handler.assign_status_list_number(txn, wallet_id)
        status_list_def.next_list_number = list_number
        status_list_def.add_list_number(list_number)
        await status_handler.create_next_status_list(txn, status_list_def)

        # Create message status list
        list_number = await status_handler.assign_status_list_number(txn, wallet_id)
        status_list_def_msg.next_list_number = list_number
        status_list_def_msg.list_number = list_number
        status_list_def_msg.add_list_number(list_number)
        await status_handler.create_next_status_list(txn, status_list_def_msg)

        list_number = await status_handler.assign_status_list_number(txn, wallet_id)
        status_list_def_msg.next_list_number = list_number
        status_list_def_msg.add_list_number(list_number)
        await status_handler.create_next_status_list(txn, status_list_def_msg)

        await status_list_def.save(txn)
        await status_list_def_msg.save(txn)
        await status_list_cred.save(txn)
        await txn.commit()
    yield
