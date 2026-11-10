import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from oid4vc.jose_util import (
    JoseAudienceError,
    JoseError,
    JoseIssuerError,
    JoseSignatureError,
    decode_hmac_jwt,
    decode_jwt,
    jwk_thumbprint,
)

from .jose_helpers import (
    b64url_encode,
    ec_key,
    ed_key,
    public_jwk,
    rsa_key,
    sign,
    sign_hmac,
)

NO_CLAIM_CHECKS = {"require": (), "verify_exp": False}


@pytest.mark.parametrize(
    "key_factory, alg",
    [(rsa_key, "RS256"), (rsa_key, "PS256"), (ec_key, "ES256"), (ed_key, "EdDSA")],
)
def test_decode_jwt_roundtrip(key_factory, alg):
    key = key_factory()
    token = sign({"typ": "JWT"}, {"hello": "world"}, key, alg)
    header, payload = decode_jwt(token, public_jwk(key), **NO_CLAIM_CHECKS)
    assert header["alg"] == alg
    assert payload == {"hello": "world"}


def test_decode_jwt_wrong_key():
    token = sign({}, {"a": 1}, ec_key(), "ES256")
    with pytest.raises(JoseSignatureError):
        decode_jwt(token, public_jwk(ec_key()), **NO_CLAIM_CHECKS)


def test_decode_jwt_rejects_symmetric_and_none():
    key = ec_key()
    token = sign({}, {"a": 1}, key, "ES256")
    _, body, sig = token.split(".")
    for alg in ("HS256", "none"):
        forged_head = b64url_encode(f'{{"alg":"{alg}"}}'.encode())
        with pytest.raises(JoseError):
            decode_jwt(f"{forged_head}.{body}.{sig}", public_jwk(key), **NO_CLAIM_CHECKS)


def test_decode_jwt_alg_key_mismatch():
    token = sign({}, {"a": 1}, rsa_key(), "RS256")
    with pytest.raises(JoseError):
        decode_jwt(token, public_jwk(ec_key()), **NO_CLAIM_CHECKS)


def test_decode_jwt_curve_must_match_alg():
    # ES256 requires P-256; a P-384 key must not be accepted for it
    key = ec.generate_private_key(ec.SECP384R1())
    token = sign({}, {"a": 1}, key, "ES384")
    forged = token.replace(token.split(".")[0], b64url_encode(b'{"alg":"ES256"}'), 1)
    with pytest.raises(JoseError, match="P-256"):
        decode_jwt(forged, public_jwk(key), **NO_CLAIM_CHECKS)


def test_decode_jwt_claims():
    key = rsa_key()
    now = int(time.time())
    claims = {"iss": "https://as.example", "aud": ["rs", "other"], "exp": now + 60}
    token = sign({}, claims, key, "RS256")
    jwk = public_jwk(key)
    _, payload = decode_jwt(token, jwk, issuer="https://as.example", audience="rs")
    assert payload["iss"] == "https://as.example"
    with pytest.raises(JoseIssuerError):
        decode_jwt(token, jwk, issuer="https://evil.example")
    with pytest.raises(JoseAudienceError):
        decode_jwt(token, jwk, audience="someone-else")
    expired = sign({}, {**claims, "exp": now - 3600}, key, "RS256")
    with pytest.raises(JoseError, match="expired"):
        decode_jwt(expired, jwk)
    with pytest.raises(JoseError, match="exp"):
        decode_jwt(sign({}, {"iss": "x"}, key, "RS256"), jwk)  # exp required


def test_decode_hmac_jwt():
    secret = "a-long-shared-secret-for-hmac-tests"
    now = int(time.time())
    token = sign_hmac({}, {"iss": "c", "exp": now + 60}, secret)
    assert decode_hmac_jwt(token, secret, issuer="c")["iss"] == "c"
    with pytest.raises(JoseSignatureError):
        decode_hmac_jwt(token, "a-different-shared-secret-value!!")
    with pytest.raises(JoseError, match="alg not allowed"):
        decode_hmac_jwt(sign({}, {"exp": now + 60}, rsa_key(), "RS256"), secret)


def test_thumbprint_ignores_order_and_extra_members():
    jwk = public_jwk(ec_key())
    reordered = {k: jwk[k] for k in reversed(list(jwk))}
    assert jwk_thumbprint(jwk) == jwk_thumbprint({**reordered, "kid": "x", "use": "sig"})


def test_thumbprint_rfc7638_example():
    # RFC 7638 §3.1
    jwk = {
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29",
    }
    assert jwk_thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_replay_cache_detects_replay_and_stays_bounded():
    from oid4vc.jose_util import ReplayCache

    cache = ReplayCache(max_entries=3, min_prune_interval=0)
    future = time.time() + 60
    assert cache.check_and_add("a", future)
    assert not cache.check_and_add("a", future)  # replay
    assert cache.check_and_add("expired", time.time() - 1)
    assert cache.check_and_add("expired", future)  # expired entries can be reused
    assert cache.check_and_add("b", future)
    # Full of live entries: the oldest is evicted, the cache never grows past the bound.
    assert cache.check_and_add("c", future)
    assert len(cache._seen) <= 3
    assert "a" not in cache._seen
    assert not cache.check_and_add("c", future)


@pytest.mark.asyncio
async def test_jwks_cache_refetches_once_for_an_unknown_kid():
    from oid4vc.jose_util import JWKSCache

    cache = JWKSCache(ttl=300, min_refresh_interval=10)
    fetches = 0

    async def fetch(jwks_uri):
        nonlocal fetches
        fetches += 1
        keys = [{"kid": "k1", "kty": "RSA", "use": "sig"}]
        cache._entries[jwks_uri] = (time.monotonic(), keys)
        return keys

    cache._fetch = fetch

    # Expired entry: one fetch, not a second one for the unknown kid.
    cache._entries["u"] = (time.monotonic() - 1000, [])
    with pytest.raises(JoseError, match="no matching key"):
        await cache.get_key("u", "unknown", None)
    assert fetches == 1

    # Live entry older than the refresh interval: refetched once for an unknown kid.
    cache._entries["u"] = (time.monotonic() - 20, [])
    with pytest.raises(JoseError, match="no matching key"):
        await cache.get_key("u", "unknown", None)
    assert fetches == 2

    # Known kid in a live entry: served from the cache.
    assert (await cache.get_key("u", "k1", None))["kid"] == "k1"
    assert fetches == 2
