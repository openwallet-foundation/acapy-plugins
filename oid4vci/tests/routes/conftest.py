from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.core.in_memory import InMemoryProfile
from aries_cloudagent.resolver.did_resolver import DIDResolver
import pytest
from unittest.mock import MagicMock
from oid4vci.jwk_resolver import JwkResolver


@pytest.fixture
def context():
    """Test AdminRequestContext."""
    yield AdminRequestContext.test_context()


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
