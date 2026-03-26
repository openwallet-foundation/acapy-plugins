import pytest

from jwt_vc_json.cred_processor import JwtVcJsonCredProcessor


@pytest.mark.asyncio
async def test__init__():
    """Test __init."""

    cred_processor = JwtVcJsonCredProcessor()

    assert cred_processor
