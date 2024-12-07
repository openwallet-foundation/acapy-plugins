import pytest
from acapy_agent.utils.testing import create_test_profile


@pytest.fixture
async def profile():
    yield await create_test_profile()
