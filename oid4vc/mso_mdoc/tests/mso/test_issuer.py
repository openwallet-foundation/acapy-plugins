import os
from binascii import hexlify

from acapy_agent.wallet.util import b64_to_bytes
from pycose.keys import CoseKey

from ...mso import MsoIssuer
from ...x509 import selfsigned_x509cert

MDOC_TYPE = "org.iso.18013.5.1.mDL"


def test_mso_sign(jwk, headers, payload):
    """Test mso_sign() method."""

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

    msoi = MsoIssuer(data=payload, private_key=cose_key, x509_cert=x509_cert)
    mso = msoi.sign(device_key=(headers.get("deviceKey") or ""), doctype=MDOC_TYPE)
    mso_signature = hexlify(mso.encode())

    assert mso_signature
