from aries_cloudagent.admin.request_context import AdminRequestContext
import pytest
from unittest.mock import MagicMock


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
