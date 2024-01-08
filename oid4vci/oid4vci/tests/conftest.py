import pytest

from aries_cloudagent.core.in_memory import InMemoryProfile


@pytest.fixture
async def profile():
    yield InMemoryProfile.test_profile()
