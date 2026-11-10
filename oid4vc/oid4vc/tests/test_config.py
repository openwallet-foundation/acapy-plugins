from acapy_agent.config.settings import Settings

from oid4vc.config import Config


def _config(**plugin_settings) -> Config:
    return Config.from_settings(
        Settings(
            {
                "plugin_config": {
                    "oid4vci": {"host": "localhost", "port": 8020, **plugin_settings}
                }
            }
        )
    )


def test_endpoint_has_no_trailing_slash():
    """The endpoint is the base of every public URL and the issuer identifier."""
    assert (
        _config(endpoint="https://issuer.example/").endpoint == "https://issuer.example"
    )
    assert _config(endpoint="https://issuer.example").endpoint == "https://issuer.example"
