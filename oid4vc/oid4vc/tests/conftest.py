import pytest
from acapy_agent.core.in_memory import InMemoryProfile


@pytest.fixture
async def profile():
    yield InMemoryProfile.test_profile()
