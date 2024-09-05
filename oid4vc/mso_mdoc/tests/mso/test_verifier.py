import pytest
import cbor2
from binascii import unhexlify

from ...mso import MsoVerifier


@pytest.mark.asyncio
async def test_mso_verify(issuer_auth):
    """Test verify_signature() method."""

    issuer_auth_bytes = unhexlify(issuer_auth)
    issuer_auth_obj = cbor2.loads(issuer_auth_bytes)
    mso_verifier = MsoVerifier(issuer_auth_obj)
    valid = mso_verifier.verify_signature()

    assert valid
