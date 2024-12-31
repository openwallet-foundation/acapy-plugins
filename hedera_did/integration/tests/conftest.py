import pytest

from .helpers import BOB, Agent

@pytest.fixture(scope="session")
def bob():
    """bob agent fixture."""
    yield Agent(BOB)
