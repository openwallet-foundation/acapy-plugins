from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture
def mock_request():
    mock_request = MagicMock()
    mock_request.context = MagicMock()

    mock_request.headers = {
        "Authorization": "Bearer valid_token",
        "x-api-key": "valid_api_key",
    }
    mock_request.method = "GET"
    mock_request.path = "/allowed-route"

    mock_request["context"].settings = {
        "plugin_config": {
            "registrar_url": "MOCK_REGISTRAR_URL",
            "resolver_url": "MOCK_RESOLVER_URL",
        },
    }

    mock_request["context"].profile = MagicMock()
    mock_request["context"].profile.settings = {
        "admin.admin_api_key": "valid_api_key",
        "admin.admin_insecure_mode": "False",
        "multitenant.enabled": "True",
        "multitenant.base_wallet_routes": "/allowed-route",
    }

    return mock_request


@pytest.fixture
def mock_create_body():
    return AsyncMock(
        return_value={
            "options": {
                "network": "testnet",
                "key_type": "ed25519",
            }
        }
    )


@pytest.fixture
def mock_update_body():
    return AsyncMock(
        return_value={
            "did": "did:cheqd:testnet:123",
            "didDocument": {
                "MOCK_KEY": "MOCK_VALUE",
            },
            "options": {
                "MOCK_OPTION_KEY": "MOCK_OPTION_VALUE",
            },
        }
    )


@pytest.fixture
def mock_deactivate_body():
    return AsyncMock(
        return_value={
            "did": "did:cheqd:testnet:123",
        }
    )


@pytest.fixture
def mock_manager():
    mock_manager = AsyncMock()
    mock_manager.create.return_value = {
        "did": "did:cheqd:testnet:123",
        "verkey": "MOCK_VERIFICATION_KEY",
    }
    mock_manager.update.return_value = {
        "MOCK_KEY": "MOCK_VALUE",
    }
    mock_manager.deactivate.return_value = {
        "MOCK_KEY": "MOCK_VALUE",
    }

    return mock_manager
