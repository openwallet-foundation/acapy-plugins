import pytest

from .helpers import Agent, HOLDER_ENDPOINT, ISSUER_ENDPOINT


@pytest.fixture(scope="session")
def holder():
    """Holder agent fixture."""
    yield Agent(name="HOLDER", base_url=HOLDER_ENDPOINT)


@pytest.fixture(scope="session")
def issuer():
    """Issuer agent fixture."""
    yield Agent(
        name="ISSUER",
        base_url=ISSUER_ENDPOINT,
    )
