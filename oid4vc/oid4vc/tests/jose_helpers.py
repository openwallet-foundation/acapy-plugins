"""Test helpers for building signed JWS with ``cryptography`` keys."""

import json
import time
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from oid4vc.dpop import access_token_hash
from oid4vc.jose_util import b64url_encode


def _int_b64(value: int, length: int | None = None) -> str:
    length = length or (value.bit_length() + 7) // 8
    return b64url_encode(value.to_bytes(length, "big"))


def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def ed_key():
    return ed25519.Ed25519PrivateKey.generate()


def public_jwk(key) -> dict:
    pub = key.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        nums = pub.public_numbers()
        size = (pub.curve.key_size + 7) // 8
        crv = {256: "P-256", 384: "P-384", 521: "P-521"}[pub.curve.key_size]
        return {
            "kty": "EC",
            "crv": crv,
            "x": _int_b64(nums.x, size),
            "y": _int_b64(nums.y, size),
        }
    if isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        return {"kty": "RSA", "n": _int_b64(nums.n), "e": _int_b64(nums.e)}
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(raw)}


def sign(header: dict, payload: dict, key, alg: str) -> str:
    signing_input = (
        b64url_encode(json.dumps({"alg": alg, **header}).encode())
        + "."
        + b64url_encode(json.dumps(payload).encode())
    ).encode()
    if alg.startswith("ES"):
        hash_alg = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}[
            alg[2:]
        ]
        r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hash_alg())))
        size = (key.curve.key_size + 7) // 8
        sig = r.to_bytes(size, "big") + s.to_bytes(size, "big")
    elif alg.startswith("RS"):
        sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg.startswith("PS"):
        sig = key.sign(
            signing_input,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    else:
        sig = key.sign(signing_input)
    return signing_input.decode() + "." + b64url_encode(sig)


def dpop_proof(
    key,
    *,
    htm="POST",
    htu="https://issuer.example/credential",
    access_token=None,
    iat=None,
    jti=None,
    typ="dpop+jwt",
    jwk=None,
) -> str:
    payload = {
        "jti": jti or str(uuid.uuid4()),
        "htm": htm,
        "htu": htu,
        "iat": int(time.time()) if iat is None else iat,
    }
    if access_token is not None:
        payload["ath"] = access_token_hash(access_token)
    return sign({"typ": typ, "jwk": jwk or public_jwk(key)}, payload, key, "ES256")


def sign_hmac(header: dict, payload: dict, secret: str, alg: str = "HS256") -> str:
    import hashlib
    import hmac

    signing_input = (
        b64url_encode(json.dumps({"alg": alg, **header}).encode())
        + "."
        + b64url_encode(json.dumps(payload).encode())
    ).encode()
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[
        alg
    ]
    sig = hmac.new(secret.encode(), signing_input, digest).digest()
    return signing_input.decode() + "." + b64url_encode(sig)
