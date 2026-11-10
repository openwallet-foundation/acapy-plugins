"""OAuth client authentication for back-channel calls from an authorization server.

Mirrors how the reference authorization server authenticates the plugin
(``auth_server/core/security/client_auth.py``), in the other direction: the
calling backend is an OAuth client of the plugin and proves it with one of

- ``private_key_jwt`` (RFC 7523 §2.2): a JWT assertion signed with the
  client's key, verified against its JWKS. For Keycloak the default key set is
  the realm JWKS, so no shared secret is needed.
- ``client_secret_jwt``: the same assertion, HMAC-signed with a shared secret.
- ``client_secret_post`` (RFC 6749 §2.3.1): ``client_id`` + ``client_secret``
  form parameters.

Credentials travel in the form body, never in ``Authorization``: on ACA-Py's
admin port in multitenant mode that header is reserved for tenant tokens.

Assertion checks: ``iss`` = ``sub`` = client_id, ``aud`` = the endpoint URL,
``exp``, a lifetime of at most five minutes, a single-use ``jti``, and any
``required_claims`` (e.g. the ``credential_issuer`` the caller acts for). With
``client_secret_post`` the required claims are checked against the form
parameters instead.
"""

import hmac
from dataclasses import dataclass
from typing import Mapping

from ..jose_util import (
    JoseAudienceError,
    JoseError,
    JoseIssuerError,
    JoseSubjectError,
    JWKSCache,
    ReplayCache,
    decode_hmac_jwt,
)
from .base import BackChannelAuthError

JWT_BEARER_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
PRIVATE_KEY_JWT = "private_key_jwt"
CLIENT_SECRET_JWT = "client_secret_jwt"
CLIENT_SECRET_POST = "client_secret_post"
AUTH_METHODS = (PRIVATE_KEY_JWT, CLIENT_SECRET_JWT, CLIENT_SECRET_POST)

# Claim / form parameter naming the credential issuer (tenant) a back-channel
# caller acts for.
CREDENTIAL_ISSUER_CLAIM = "credential_issuer"

MAX_ASSERTION_LIFETIME = 300
CLOCK_LEEWAY = 10


@dataclass
class BackChannelClient:
    """How a back-channel client is expected to authenticate."""

    client_id: str
    auth_method: str = PRIVATE_KEY_JWT
    client_secret: str | None = None
    jwks_uri: str | None = None
    audience: str | None = None


async def authenticate_client(
    client: BackChannelClient,
    params: Mapping[str, str],
    endpoint_url: str,
    *,
    jwks_cache: JWKSCache,
    replay_cache: ReplayCache,
    required_claims: Mapping[str, str] | None = None,
) -> None:
    """Authenticate a back-channel request; raise ``BackChannelAuthError``."""
    required_claims = required_claims or {}
    if client.auth_method not in AUTH_METHODS:
        raise BackChannelAuthError(f"unsupported auth method {client.auth_method!r}")

    presented_id = params.get("client_id")
    if presented_id is not None and presented_id != client.client_id:
        raise BackChannelAuthError("unknown client_id")

    if client.auth_method == CLIENT_SECRET_POST:
        secret = params.get("client_secret")
        if not client.client_secret or not secret or presented_id is None:
            raise BackChannelAuthError("client_id and client_secret are required")
        if not hmac.compare_digest(secret.encode(), client.client_secret.encode()):
            raise BackChannelAuthError("invalid client_secret")
        for name, value in required_claims.items():
            if params.get(name) != value:
                raise BackChannelAuthError(f"{name} mismatch")
        return

    if params.get("client_assertion_type") != JWT_BEARER_ASSERTION:
        raise BackChannelAuthError("client_assertion_type must be jwt-bearer")
    assertion = params.get("client_assertion")
    if not assertion:
        raise BackChannelAuthError("client_assertion is required")

    claim_checks = {
        "audience": client.audience or endpoint_url,
        "issuer": client.client_id,
        "subject": client.client_id,
        "leeway": CLOCK_LEEWAY,
        "require": ("exp", "iat", "jti", "iss", "sub", "aud"),
    }
    try:
        if client.auth_method == PRIVATE_KEY_JWT:
            if not client.jwks_uri:
                raise BackChannelAuthError("no JWKS configured for private_key_jwt")
            _, payload = await jwks_cache.decode(
                client.jwks_uri, assertion, **claim_checks
            )
        else:
            if not client.client_secret:
                raise BackChannelAuthError("no secret configured for client_secret_jwt")
            payload = decode_hmac_jwt(assertion, client.client_secret, **claim_checks)
    except JoseAudienceError as err:
        raise BackChannelAuthError("client_assertion audience mismatch") from err
    except (JoseIssuerError, JoseSubjectError) as err:
        raise BackChannelAuthError(
            "client_assertion iss/sub must equal client_id"
        ) from err
    except JoseError as err:
        raise BackChannelAuthError(f"invalid client_assertion: {err}") from err

    for name, value in required_claims.items():
        if payload.get(name) != value:
            raise BackChannelAuthError(f"client_assertion {name} mismatch")
    # exp/iat/nbf validity was checked by PyJWT; also cap the lifetime.
    if payload["exp"] - payload["iat"] > MAX_ASSERTION_LIFETIME:
        raise BackChannelAuthError("client_assertion lifetime is not acceptable")
    jti = payload["jti"]
    if not isinstance(jti, str):
        raise BackChannelAuthError("client_assertion jti must be a string")
    if not replay_cache.check_and_add(
        f"{client.client_id}:{jti}", payload["exp"] + CLOCK_LEEWAY
    ):
        raise BackChannelAuthError("client_assertion jti replayed")
