from unittest.mock import MagicMock

from aries_cloudagent.core.profile import Profile
import pytest
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.core.in_memory import InMemoryProfile
from aries_cloudagent.resolver.did_resolver import DIDResolver

from oid4vc.jwk_resolver import JwkResolver
from oid4vc.cred_processor import CredProcessors
from jwt_vc_json import JwtVcJsonCredProcessor


@pytest.fixture
def resolver():
    """Test DIDResolver."""
    yield DIDResolver([JwkResolver()])


@pytest.fixture
def profile(resolver: DIDResolver):
    """Test Profile."""
    processors = CredProcessors([JwtVcJsonCredProcessor()])
    yield InMemoryProfile.test_profile(
        {
            "admin.admin_insecure_mode": True,
            "plugin_config": {
                "oid4vci": {
                    "endpoint": "http://localhost:8020",
                    "host": "0.0.0.0",
                    "port": 8020,
                }
            }
        },
        {
            DIDResolver: resolver,
            CredProcessors: processors,
        },
    )


@pytest.fixture
def context(profile: Profile):
    """Test AdminRequestContext."""
    context = AdminRequestContext.test_context({}, profile)
    yield context


@pytest.fixture
def req(context: AdminRequestContext):
    """Test web.Request."""
    items = {"context": context}
    mock = MagicMock()
    mock.__getitem__ = lambda _, k: items[k]
    yield mock
