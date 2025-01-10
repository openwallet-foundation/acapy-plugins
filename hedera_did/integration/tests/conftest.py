import pytest

from .helpers import Agent, HOLDER_ENDPOINT, ISSUER_ENDPOINT

@pytest.fixture(scope="session")
def holder():
    """Holder agent fixture."""
    yield Agent("HOLDER", HOLDER_ENDPOINT)

@pytest.fixture(scope="session")
def issuer():
    """Issuer agent fixture."""
    yield Agent("ISSUER", ISSUER_ENDPOINT)
