from unittest import IsolatedAsyncioTestCase

from ..config import MultitenantProviderConfig, TokenExpiryConfig, get_config


class TestConfig(IsolatedAsyncioTestCase):
    async def test_get_token_expiry_delta(self):
        token_config = TokenExpiryConfig()
        assert token_config.get_token_expiry_delta().days == 364
        assert token_config.get_token_expiry_delta().seconds == 0
        assert token_config.get_token_expiry_delta().microseconds == 0

        token_config = TokenExpiryConfig(units="days", amount=7)
        assert token_config.get_token_expiry_delta().days == 7
        assert token_config.get_token_expiry_delta().seconds == 0
        assert token_config.get_token_expiry_delta().microseconds == 0

        token_config = TokenExpiryConfig(units="hours", amount=5)
        assert token_config.get_token_expiry_delta().days == 0
        assert token_config.get_token_expiry_delta().seconds == 5 * 60 * 60
        assert token_config.get_token_expiry_delta().microseconds == 0

        token_config = TokenExpiryConfig(units="minutes", amount=3)
        assert token_config.get_token_expiry_delta().days == 0
        assert token_config.get_token_expiry_delta().seconds == 3 * 60
        assert token_config.get_token_expiry_delta().microseconds == 0

        # invalid defaults to one year
        token_config = TokenExpiryConfig(units="seconds", amount=100)
        assert token_config.get_token_expiry_delta().days == 364
        assert token_config.get_token_expiry_delta().seconds == 0
        assert token_config.get_token_expiry_delta().microseconds == 0

    async def test_get_config_without_settings_returns_default(self):
        config = get_config({})
        assert isinstance(config, MultitenantProviderConfig)

    async def test_get_config_with_settings_returns_valid_config(self):
        settings = {
            "plugin_config": {"multitenant_provider": {"errors": {"testing...": True}}}
        }
        config = get_config(settings)
        assert isinstance(config, MultitenantProviderConfig)
