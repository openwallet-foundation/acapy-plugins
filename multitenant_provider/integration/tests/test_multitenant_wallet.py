"""Integration tests for Multi Tenant Provider."""

import copy
import time
import uuid

import pytest

from . import ADMIN, Agent


@pytest.fixture(scope="session")
def admin():
    """resolver agent fixture."""
    yield Agent(ADMIN)


create_wallet_playload = {
    "extra_settings": {},
    "image_url": "https://aries.ca/images/sample.png",
    "key_management_mode": "managed",
    "label": "Provider",
    "wallet_dispatch_type": "default",
    "wallet_key": "test-wallet-key",  # replace
    "wallet_key_derivation": "RAW",
    "wallet_name": "test-wallet-name",  # replace
    "wallet_type": "askar",
    "wallet_webhook_urls": ["http://localhost:8022/webhooks"],
}


def test_create_wallet_token_and_authenticate(admin):
    wallet_uuid = str(uuid.uuid4())

    payload = copy.deepcopy(create_wallet_playload)
    payload["wallet_key"] = "test_wallet_key_" + wallet_uuid
    payload["wallet_name"] = "test_wallet_name_" + wallet_uuid
    wallet_config = admin.create_wallet(payload)

    time.sleep(0.1)

    response = admin.get_connections(wallet_config["token"])

    assert response.status_code == 200


def test_creating_and_authenticating_multiple_wallets(admin):
    wallet_uuid = str(uuid.uuid4())
    test_wallet_one = "test_wallet_one" + wallet_uuid
    test_wallet_two = "test_wallet_two" + wallet_uuid

    payload = copy.deepcopy(create_wallet_playload)
    payload["wallet_key"] = "test_wallet_key_one_" + wallet_uuid
    payload["wallet_name"] = test_wallet_one
    wallet_config_1 = admin.create_wallet(payload)

    payload["wallet_key"] = "test_wallet_key_two_" + wallet_uuid
    payload["wallet_name"] = test_wallet_two
    wallet_config_2 = admin.create_wallet(payload)

    time.sleep(0.1)

    wallets = admin.get_wallets()
    wallet_names = (wallet["settings"]["wallet.name"] for wallet in wallets["results"])

    assert test_wallet_one in wallet_names
    assert test_wallet_two in wallet_names

    admin.get_connections(wallet_config_1["token"])

    time.sleep(0.1)

    admin.get_connections(wallet_config_2["token"])


def test_deleting_wallet_invalidates_token(admin):
    wallet_uuid = str(uuid.uuid4())

    payload = copy.deepcopy(create_wallet_playload)
    payload["wallet_key"] = "test_wallet_key_" + wallet_uuid
    payload["wallet_name"] = "test_wallet_name_" + wallet_uuid
    wallet_config = admin.create_wallet(payload)

    time.sleep(0.1)

    admin.remove_wallet(wallet_config["wallet_id"], {})

    time.sleep(0.1)

    response = admin.get_connections(wallet_config["token"])
    assert response.status_code == 401


def get_multiple_tokens_from_new_wallet(admin: Agent, remove_wallet: bool = False):
    wallet_uuid = str(uuid.uuid4())
    wallet_key = "test_wallet_key_" + wallet_uuid
    payload = copy.deepcopy(create_wallet_playload)
    payload["wallet_key"] = wallet_key
    payload["wallet_name"] = "test_wallet_name_" + wallet_uuid
    wallet_config = admin.create_wallet(payload)

    tokens = []
    tokens.append(wallet_config["token"])

    tokens.append(
        admin.get_token(wallet_config["wallet_id"], {"wallet_key": wallet_key})["token"]
    )
    tokens.append(
        admin.get_token(wallet_config["wallet_id"], {"wallet_key": wallet_key})["token"]
    )

    if remove_wallet:
        admin.remove_wallet(wallet_config["wallet_id"], {})

    return tokens


def test_creating_multiple_tokens_for_one_wallet_and_have_authorization(admin):
    for token in get_multiple_tokens_from_new_wallet(admin):
        admin.get_connections(token)


def test_creating_multiple_tokens_for_one_wallet_and_then_deleting_wallet_invalidates_tokens(
    admin,
):
    for token in get_multiple_tokens_from_new_wallet(admin, remove_wallet=True):
        response = admin.get_connections(token)
        assert response.status_code == 401
