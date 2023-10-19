"""Integration tests for Multi Tenant Provider."""

import time
import uuid

import pytest

from . import ADMIN, Agent


@pytest.fixture(scope="session")
def admin():
    """resolver agent fixture."""
    yield Agent(ADMIN)


def test_create_wallet_token_and_authenticate(admin):
    wallet_uuid = str(uuid.uuid4())
    test_wallet_name = "test_wallet_name_" + wallet_uuid
    test_wallet_key = "test_wallet_key_" + wallet_uuid

    wallet_config = admin.create_wallet(
        {
            "extra_settings": {},
            "image_url": "https://aries.ca/images/sample.png",
            "key_management_mode": "managed",
            "label": "Provider",
            "wallet_dispatch_type": "default",
            "wallet_key": test_wallet_key,
            "wallet_key_derivation": "RAW",
            "wallet_name": test_wallet_name,
            "wallet_type": "askar",
            "wallet_webhook_urls": ["http://localhost:8022/webhooks"],
        }
    )

    time.sleep(0.1)

    response = admin.get_connections(wallet_config["token"])

    assert response.status_code == 200


def test_creating_and_authenticating_multiple_wallets(admin):
    wallet_uuid = str(uuid.uuid4())
    test_wallet_one = "test_wallet_one" + wallet_uuid
    test_wallet_two = "test_wallet_two" + wallet_uuid

    payload = {
        "extra_settings": {},
        "image_url": "https://aries.ca/images/sample.png",
        "key_management_mode": "managed",
        "label": "Provider",
        "wallet_dispatch_type": "default",
        "wallet_key": "replace_me",
        "wallet_key_derivation": "RAW",
        "wallet_name": 'replace_me',
        "wallet_type": "askar",
        "wallet_webhook_urls": ["http://localhost:8022/webhooks"],
    }
    payload['wallet_key'] = "test_wallet_key_one_" + wallet_uuid
    payload['wallet_name'] = test_wallet_one
    wallet_config_1 = admin.create_wallet(payload)

    payload['wallet_key'] = "test_wallet_key_two_" + wallet_uuid
    payload['wallet_name'] = test_wallet_two
    wallet_config_2 = admin.create_wallet(payload)

    time.sleep(0.1)

    wallets = admin.get_wallets()
    wallet_names = map(
        lambda wallet: wallet["settings"]["wallet.name"], wallets["results"])

    assert test_wallet_one in wallet_names
    assert test_wallet_two in wallet_names

    admin.get_connections(wallet_config_1["token"])

    time.sleep(0.1)

    admin.get_connections(wallet_config_2["token"])


def test_deleting_wallet_invalidates_token(admin):
    wallet_uuid = str(uuid.uuid4())
    test_wallet_name = "test_wallet_name_" + wallet_uuid
    test_wallet_key = "test_wallet_key_" + wallet_uuid

    wallet_config = admin.create_wallet(
        {
            "extra_settings": {},
            "image_url": "https://aries.ca/images/sample.png",
            "key_management_mode": "managed",
            "label": "Provider",
            "wallet_dispatch_type": "default",
            "wallet_key": test_wallet_key,
            "wallet_key_derivation": "RAW",
            "wallet_name": test_wallet_name,
            "wallet_type": "askar",
            "wallet_webhook_urls": ["http://localhost:8022/webhooks"],
        }
    )

    time.sleep(0.1)

    response = admin.remove_wallet(wallet_config["wallet_id"])

    time.sleep(0.1)

    response = admin.get_connections(wallet_config["token"])
    assert response.status_code == 401
