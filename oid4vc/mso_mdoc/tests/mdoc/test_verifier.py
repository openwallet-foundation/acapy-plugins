import pytest

from ...mdoc import mdoc_verify, MdocVerifyResult


@pytest.mark.asyncio
def test_mdoc_verify(mso_mdoc):
    """Test mdoc_sign() method."""

    result: MdocVerifyResult = mdoc_verify(mso_mdoc)

    assert result
