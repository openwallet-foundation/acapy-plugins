import pytest

from ..cred_processor import CredProcessor


@pytest.mark.asyncio
async def test__init__():
    """Test __init."""

    cred_processor = CredProcessor()

    assert cred_processor
