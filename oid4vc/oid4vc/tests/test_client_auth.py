import time
import uuid

import pytest

from oid4vc.auth_providers import BackChannelAuthError
from oid4vc.auth_providers.client_auth import (
    CLIENT_SECRET_JWT,
    CLIENT_SECRET_POST,
    JWT_BEARER_ASSERTION,
    BackChannelClient,
    authenticate_client,
)
from oid4vc.jose_util import JWKSCache, ReplayCache

from .jose_helpers import public_jwk, rsa_key, sign, sign_hmac

CLIENT_ID = "https://kc.example/realms/oid4vci"
ENDPOINT = "http://issuer:3001/oid4vci/pre-auth/redeem"
JWKS_URI = "http://keycloak:8080/realms/oid4vci/protocol/openid-connect/certs"
SECRET = "s3cr3t-s3cr3t-s3cr3t-s3cr3t-s3cr3t"


@pytest.fixture
def key():
    return rsa_key()


@pytest.fixture
def jwks(key):
    cache = JWKSCache()
    cache._entries[JWKS_URI] = (
        time.monotonic(),
        [{**public_jwk(key), "kid": "k1", "alg": "RS256", "use": "sig"}],
    )
    return cache


def _claims(**overrides):
    now = int(time.time())
    claims = {
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "aud": ENDPOINT,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
        **overrides,
    }
    return {k: v for k, v in claims.items() if v is not None}


def _params(assertion, **extra):
    return {
        "client_assertion_type": JWT_BEARER_ASSERTION,
        "client_assertion": assertion,
        **extra,
    }


async def _auth(client, params, jwks, replay=None):
    await authenticate_client(
        client, params, ENDPOINT, jwks_cache=jwks, replay_cache=replay or ReplayCache()
    )


@pytest.mark.asyncio
async def test_private_key_jwt(key, jwks):
    client = BackChannelClient(client_id=CLIENT_ID, jwks_uri=JWKS_URI)
    replay = ReplayCache()
    assertion = sign({"kid": "k1"}, _claims(), key, "RS256")
    await _auth(client, _params(assertion, client_id=CLIENT_ID), jwks, replay)
    with pytest.raises(BackChannelAuthError, match="replayed"):
        await _auth(client, _params(assertion), jwks, replay)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"aud": "http://issuer:8082"}, "audience"),
        ({"iss": "someone-else"}, "iss/sub"),
        ({"sub": "generic-holder"}, "iss/sub"),
        ({"exp": int(time.time()) + 3600}, "lifetime"),
        ({"exp": int(time.time()) - 3600}, "expired"),
        ({"jti": None}, "jti"),
    ],
)
async def test_private_key_jwt_rejected(key, jwks, overrides, match):
    client = BackChannelClient(client_id=CLIENT_ID, jwks_uri=JWKS_URI)
    assertion = sign({"kid": "k1"}, _claims(**overrides), key, "RS256")
    with pytest.raises(BackChannelAuthError, match=match):
        await _auth(client, _params(assertion), jwks)


@pytest.mark.asyncio
async def test_private_key_jwt_wrong_key(jwks):
    client = BackChannelClient(client_id=CLIENT_ID, jwks_uri=JWKS_URI)
    assertion = sign({"kid": "k1"}, _claims(), rsa_key(), "RS256")
    with pytest.raises(BackChannelAuthError, match="invalid client_assertion"):
        await _auth(client, _params(assertion), jwks)


@pytest.mark.asyncio
async def test_assertion_type_and_presence(key, jwks):
    client = BackChannelClient(client_id=CLIENT_ID, jwks_uri=JWKS_URI)
    assertion = sign({"kid": "k1"}, _claims(), key, "RS256")
    with pytest.raises(BackChannelAuthError, match="jwt-bearer"):
        await _auth(client, {"client_assertion": assertion}, jwks)
    with pytest.raises(BackChannelAuthError, match="required"):
        await _auth(client, {"client_assertion_type": JWT_BEARER_ASSERTION}, jwks)
    with pytest.raises(BackChannelAuthError, match="client_id"):
        await _auth(client, _params(assertion, client_id="other"), jwks)


@pytest.mark.asyncio
async def test_audience_override(key, jwks):
    client = BackChannelClient(
        client_id=CLIENT_ID, jwks_uri=JWKS_URI, audience="https://issuer-admin.internal"
    )
    assertion = sign(
        {"kid": "k1"}, _claims(aud="https://issuer-admin.internal"), key, "RS256"
    )
    await _auth(client, _params(assertion), jwks)


@pytest.mark.asyncio
async def test_client_secret_jwt(jwks):
    client = BackChannelClient(
        client_id=CLIENT_ID, auth_method=CLIENT_SECRET_JWT, client_secret=SECRET
    )
    await _auth(client, _params(sign_hmac({}, _claims(), SECRET)), jwks)
    with pytest.raises(BackChannelAuthError):
        await _auth(client, _params(sign_hmac({}, _claims(), "wrong-secret")), jwks)


@pytest.mark.asyncio
async def test_client_secret_post(jwks):
    client = BackChannelClient(
        client_id=CLIENT_ID, auth_method=CLIENT_SECRET_POST, client_secret=SECRET
    )
    await _auth(client, {"client_id": CLIENT_ID, "client_secret": SECRET}, jwks)
    with pytest.raises(BackChannelAuthError):
        await _auth(client, {"client_id": CLIENT_ID, "client_secret": "nope"}, jwks)
    with pytest.raises(BackChannelAuthError):
        await _auth(client, {"client_secret": SECRET}, jwks)


@pytest.mark.asyncio
async def test_unsupported_method(jwks):
    client = BackChannelClient(client_id=CLIENT_ID, auth_method="client_secret_basic")
    with pytest.raises(BackChannelAuthError, match="unsupported"):
        await _auth(client, {}, jwks)


@pytest.mark.asyncio
async def test_required_claims_assertion(key, jwks):
    client = BackChannelClient(client_id=CLIENT_ID, jwks_uri=JWKS_URI)
    required = {"credential_issuer": "https://issuer.example/tenant/t1"}

    async def auth(claims):
        assertion = sign({"kid": "k1"}, _claims(**claims), key, "RS256")
        await authenticate_client(
            client,
            _params(assertion),
            ENDPOINT,
            jwks_cache=jwks,
            replay_cache=ReplayCache(),
            required_claims=required,
        )

    await auth(required)
    with pytest.raises(BackChannelAuthError, match="credential_issuer"):
        await auth({"credential_issuer": "https://issuer.example/tenant/t2"})
    with pytest.raises(BackChannelAuthError, match="credential_issuer"):
        await auth({})


@pytest.mark.asyncio
async def test_required_claims_client_secret_post(jwks):
    client = BackChannelClient(
        client_id=CLIENT_ID, auth_method=CLIENT_SECRET_POST, client_secret=SECRET
    )
    required = {"credential_issuer": "https://issuer.example/tenant/t1"}
    params = {"client_id": CLIENT_ID, "client_secret": SECRET}
    await authenticate_client(
        client,
        {**params, **required},
        ENDPOINT,
        jwks_cache=jwks,
        replay_cache=ReplayCache(),
        required_claims=required,
    )
    with pytest.raises(BackChannelAuthError, match="credential_issuer"):
        await authenticate_client(
            client,
            params,
            ENDPOINT,
            jwks_cache=jwks,
            replay_cache=ReplayCache(),
            required_claims=required,
        )
