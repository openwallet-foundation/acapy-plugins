import time
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from oid4vc.auth_providers import AuthContext, BackChannelAuthError, InvalidTokenError
from oid4vc.jose_util import JWKSCache
from oid4vc.tests.jose_helpers import public_jwk, rsa_key, sign

from oid4vc.auth_providers.client_auth import JWT_BEARER_ASSERTION
from oid4vc_keycloak.provider import KeycloakProvider

REALM = "https://kc.example/realms/oid4vci"
ISSUER = "https://issuer.example"
JWKS_URI = "http://keycloak:8080/realms/oid4vci/protocol/openid-connect/certs"


@pytest.fixture
def realm_key():
    return rsa_key()


@pytest.fixture
def provider(realm_key):
    cache = JWKSCache()
    jwk = {**public_jwk(realm_key), "kid": "realm-1", "alg": "RS256", "use": "sig"}
    cache._entries[JWKS_URI] = (time.monotonic(), [jwk])
    return KeycloakProvider(jwks_cache=cache)


@pytest.fixture
def ctx():
    profile = SimpleNamespace(settings={})
    return AuthContext(
        profile,
        MagicMock(endpoint=ISSUER),
        {
            "type": "keycloak",
            "public_url": REALM,
            "private_url": "http://keycloak:8080/realms/oid4vci",
        },
    )


def _token(key, header_typ="JWT", **claims):
    payload = {
        "iss": REALM,
        "aud": [ISSUER, "account"],
        "exp": int(time.time()) + 60,
        "iat": int(time.time()),
        "sub": "generic-holder",
        "typ": "DPoP",
        "refresh_id": "refresh-1",
        "cnf": {"jkt": "thumb"},
        **claims,
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    return sign({"typ": header_typ, "kid": "realm-1"}, payload, key, "RS256")


@pytest.mark.asyncio
async def test_valid_access_token(provider, ctx, realm_key):
    result = await provider.validate_access_token(ctx, _token(realm_key))
    assert result.verified
    # Unbound access tokens (DPoP off), including Keycloak's lower-case variant.
    for typ in ("Bearer", "bearer"):
        unbound = await provider.validate_access_token(ctx, _token(realm_key, typ=typ))
        assert unbound.verified
    assert provider.exchange_key(ctx, result.payload) == "refresh-1"
    assert provider.require_dpop(ctx)
    assert provider.authorization_servers(ctx) == [REALM]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://evil.example/realms/x"},
        {"aud": "https://other-issuer.example"},
        {"exp": int(time.time()) - 3600},
        {"refresh_id": None},
        # Realm-signed JWTs that are not access tokens (refresh token, no typ)
        {"typ": "Refresh", "aud": ISSUER},
        {"typ": "Offline", "aud": ISSUER},
        {"typ": "ID", "aud": ISSUER},
        {"typ": None},
    ],
)
async def test_rejected_access_tokens(provider, ctx, realm_key, claims):
    with pytest.raises(InvalidTokenError):
        await provider.validate_access_token(ctx, _token(realm_key, **claims))


@pytest.mark.asyncio
async def test_token_signed_by_other_key(provider, ctx):
    with pytest.raises(InvalidTokenError):
        await provider.validate_access_token(ctx, _token(rsa_key()))


@pytest.mark.asyncio
async def test_custom_claim_and_dpop_settings(provider, realm_key):
    ctx = AuthContext(
        SimpleNamespace(settings={}),
        MagicMock(endpoint=ISSUER),
        {
            "type": "keycloak",
            "public_url": REALM,
            "jwks_uri": JWKS_URI,
            "refresh_id_claim": "exchange",
            "require_dpop": False,
        },
    )
    result = await provider.validate_access_token(
        ctx, _token(realm_key, refresh_id=None, exchange="ex-9")
    )
    assert provider.exchange_key(ctx, result.payload) == "ex-9"
    assert not provider.require_dpop(ctx)


REDEEM_URL = "http://issuer:3001/oid4vci/pre-auth/redeem"


def _assertion(key, **claims):
    now = int(time.time())
    payload = {
        "iss": REALM,
        "sub": REALM,
        "aud": REDEEM_URL,
        "credential_issuer": ISSUER,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
        **claims,
    }
    return sign({"kid": "realm-1"}, payload, key, "RS256")


def _params(assertion):
    return {"client_assertion_type": JWT_BEARER_ASSERTION, "client_assertion": assertion}


@pytest.mark.asyncio
async def test_back_channel_private_key_jwt_with_realm_key(provider, ctx, realm_key):
    # Default: private_key_jwt, client_id = realm issuer, keys = realm JWKS
    params = _params(_assertion(realm_key))
    await provider.authenticate_back_channel(ctx, params, REDEEM_URL)
    with pytest.raises(BackChannelAuthError, match="replayed"):
        await provider.authenticate_back_channel(ctx, params, REDEEM_URL)


@pytest.mark.asyncio
async def test_back_channel_rejects_access_token(provider, ctx, realm_key):
    # A realm access token is signed by the same key but is not a client assertion
    with pytest.raises(BackChannelAuthError):
        await provider.authenticate_back_channel(
            ctx, _params(_token(realm_key)), REDEEM_URL
        )


@pytest.mark.asyncio
async def test_back_channel_must_name_this_tenant(provider, ctx, realm_key):
    # The realm's assertion must name this tenant's credential issuer
    for claims in (
        {"credential_issuer": f"{ISSUER}/tenant/other"},
        {"credential_issuer": None},
    ):
        with pytest.raises(BackChannelAuthError, match="credential_issuer"):
            await provider.authenticate_back_channel(
                ctx, _params(_assertion(realm_key, **claims)), REDEEM_URL
            )


@pytest.mark.asyncio
async def test_back_channel_wrong_endpoint(provider, ctx, realm_key):
    with pytest.raises(BackChannelAuthError, match="audience"):
        await provider.authenticate_back_channel(
            ctx,
            _params(_assertion(realm_key)),
            "http://other-issuer:3001/oid4vci/pre-auth/redeem",
        )


@pytest.mark.asyncio
async def test_back_channel_client_secret_post(provider, realm_key):
    ctx = AuthContext(
        SimpleNamespace(settings={}),
        MagicMock(endpoint=ISSUER),
        {
            "type": "keycloak",
            "public_url": REALM,
            "redeem_client": {
                "auth_method": "client_secret_post",
                "client_id": "keycloak-redeem",
                "client_secret": "a-long-shared-secret",
            },
        },
    )
    await provider.authenticate_back_channel(
        ctx,
        {
            "client_id": "keycloak-redeem",
            "client_secret": "a-long-shared-secret",
            "credential_issuer": ISSUER,
        },
        REDEEM_URL,
    )
    with pytest.raises(BackChannelAuthError):
        await provider.authenticate_back_channel(
            ctx, _params(_assertion(realm_key)), REDEEM_URL
        )
