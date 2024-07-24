from unittest.mock import MagicMock

import pytest
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.core.in_memory import InMemoryProfile
from aries_cloudagent.resolver.did_resolver import DIDResolver

from oid4vci.jwk_resolver import JwkResolver


@pytest.fixture
def context():
    """Test AdminRequestContext."""
    context = AdminRequestContext.test_context()
    context.update_settings(
        {
            "plugin_config": {
                "oid4vci": {
                    "endpoint": "http://localhost:8020",
                    "host": "0.0.0.0",
                    "port": 8020,
                    "cred_handler": '{"jwt_vc_json": "jwt_vc_json.v1_0"}',
                }
            }
        }
    )
    yield context


@pytest.fixture
def req(context: AdminRequestContext):
    """Test web.Request."""
    items = {"context": context}
    mock = MagicMock()
    mock.__getitem__ = lambda _, k: items[k]
    yield mock


@pytest.fixture
def resolver():
    """Test DIDResolver."""
    yield DIDResolver([JwkResolver()])


@pytest.fixture
def profile(resolver: DIDResolver):
    """Test Profile."""
    yield InMemoryProfile.test_profile(
        {},
        {
            DIDResolver: resolver,
        },
    )
