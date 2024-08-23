import pytest

from ...mdoc import mdoc_sign


@pytest.mark.asyncio
def test_mdoc_sign(jwk, headers, payload):
    """Test mdoc_sign() method."""

    mso_mdoc = mdoc_sign(jwk, headers, payload)

    assert mso_mdoc
