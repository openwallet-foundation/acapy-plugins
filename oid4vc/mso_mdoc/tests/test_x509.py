import os

import pytest
from acapy_agent.wallet.util import b64_to_bytes
from pycose.keys import CoseKey

from ..x509 import selfsigned_x509cert


@pytest.mark.asyncio
def test_selfsigned_x509cert(jwk, headers, payload):
    """Test selfsigned_x509cert() method."""

    pk_dict = {
        "KTY": jwk.get("kty") or "",  # OKP, EC
        "CURVE": jwk.get("crv") or "",  # ED25519, P_256
        "ALG": "EdDSA" if jwk.get("kty") == "OKP" else "ES256",
        "D": b64_to_bytes(jwk.get("d") or "", True),  # EdDSA
        "X": b64_to_bytes(jwk.get("x") or "", True),  # EdDSA, EcDSA
        "Y": b64_to_bytes(jwk.get("y") or "", True),  # EcDSA
        "KID": os.urandom(32),
    }
    cose_key = CoseKey.from_dict(pk_dict)

    x509_cert = selfsigned_x509cert(private_key=cose_key)

    assert x509_cert
