"""Tenant client authentication (private_key_jwt, client_secret_basic)."""

import json
from typing import Any, Mapping

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
)
from joserfc import jwt
from joserfc.jwk import KeySet
from sqlalchemy.ext.asyncio import AsyncSession

from core.consts import CLIENT_AUTH_METHODS, SUPPORTED_SIGNING_ALGS
from core.consts import ClientAuthMethod as CLIENT_AUTH_METHOD
from core.crypto.crypto import verify_secret_pbkdf2
from core.models import Client as AuthClient
from core.repositories.client_repository import ClientRepository
from core.security.jwks_cache import JWKSCache
from core.security.utils import jwt_header_unverified, jwt_payload_unverified
from core.utils.logging import get_logger
from tenant.deps import get_db_session
from tenant.security.jti_cache import JtiCache

logger = get_logger(__name__)

_pkjwt_jti_cache = JtiCache(window=300)
_jwks_uri_cache = JWKSCache(ttl=300)

basic_security = HTTPBasic(auto_error=False)
bearer_security = HTTPBearer(auto_error=False)


async def _load_jwks(client, kid: str | None = None) -> KeySet | None:
    jwks_data: dict | None = None
    if isinstance(client.jwks, dict):
        jwks_data = client.jwks
    elif client.jwks and isinstance(client.jwks, str):
        try:
            jwks_data = json.loads(client.jwks)
        except Exception:
            return None
    if jwks_data:
        return KeySet.import_key_set(jwks_data)
    if client.jwks_uri:
        return await _jwks_uri_cache.get_jwks(client.jwks_uri, kid=kid)
    return None


def _audiences_for(request: Request) -> list[str]:
    # Full URL without query
    url = str(request.url)
    base = url.split("?", 1)[0]
    return [base]


def _validate_jwt_alg(token: str, expected_alg: str):
    """Validate the 'alg' field in the JWT header."""
    header = jwt_header_unverified(token)
    if header.get("alg") != expected_alg:
        raise HTTPException(status_code=401, detail="invalid_alg")


def _validate_jwt_claims(decoded: dict[str, Any], request: Request):
    """Validate standard JWT claims."""
    for claim in ("iss", "sub", "aud", "exp", "iat", "jti"):
        if claim not in decoded:
            raise HTTPException(status_code=401, detail=f"missing_{claim}")
    aud = decoded.get("aud")
    expected_aud = _audiences_for(request)
    if isinstance(aud, str):
        aud = [aud]
    if not aud or not any(a in expected_aud for a in aud):
        raise HTTPException(status_code=401, detail="invalid_audience")


async def _decode_and_validate_jwt(
    token: str,
    key_material: Any,
    request: Request,
    db: AsyncSession,
    expected_alg: str | None = None,
) -> Mapping[str, Any]:
    """Decode, validate, and return JWT claims."""

    if expected_alg:
        _validate_jwt_alg(token, expected_alg)
        algorithms = [expected_alg]
    else:
        # No client-level restriction; still limit to asymmetric algs
        header = jwt_header_unverified(token)
        alg = header.get("alg")
        if alg not in SUPPORTED_SIGNING_ALGS:
            raise HTTPException(status_code=401, detail="unsupported_alg")
        algorithms = [alg]

    try:
        result = jwt.decode(token, key_material, algorithms=algorithms)  # type: ignore[arg-type]
        claims = result.claims
        claims_registry = jwt.JWTClaimsRegistry()
        claims_registry.validate(claims, leeway=30)
        _validate_jwt_claims(claims, request)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("client_assertion decode/validate failed: %s", exc)
        raise HTTPException(status_code=401, detail="invalid_client") from exc

    if not isinstance(claims, Mapping):
        logger.warning("JWT claims is not a mapping")
        raise HTTPException(status_code=401, detail="invalid_client")

    # Replay check (RFC 7523 §3) — store until JWT expires
    jti = claims.get("jti")
    exp = claims.get("exp")
    if not await _pkjwt_jti_cache.check_and_store(jti, db, expires_at=exp):
        logger.warning("replayed jti=%s for sub=%s", jti, claims.get("sub"))
        raise HTTPException(status_code=401, detail="invalid_client")

    return claims


async def _authenticate_private_key_jwt(
    client: AuthClient,
    token: str,
    request: Request,
    db: AsyncSession,
) -> Mapping[str, Any]:
    """Validate private_key_jwt assertions."""

    header = jwt_header_unverified(token)
    kid = header.get("kid")
    keys = await _load_jwks(client, kid=kid)
    if not keys or not keys.keys:
        logger.warning("no keys found for client=%s kid=%s", client.client_id, kid)
        raise HTTPException(status_code=401, detail="invalid_client")

    claims = await _decode_and_validate_jwt(
        token,
        keys,
        request,
        db,
        expected_alg=client.client_auth_signing_alg,
    )

    # iss and sub must match client_id (RFC 7523 §3)
    if str(claims.get("iss")) != str(client.client_id):
        logger.warning(
            "iss mismatch: got %s, expected %s",
            claims.get("iss"),
            client.client_id,
        )
        raise HTTPException(status_code=401, detail="invalid_client")
    if str(claims.get("sub")) != str(client.client_id):
        logger.warning(
            "sub mismatch: got %s, expected %s",
            claims.get("sub"),
            client.client_id,
        )
        raise HTTPException(status_code=401, detail="invalid_client")

    return claims


def _authenticate_client_secret_basic(client: AuthClient, token: str) -> None:
    """Validate client_secret_basic credentials."""

    secret_hash = client.client_secret
    if secret_hash and token and verify_secret_pbkdf2(token, secret_hash):
        return
    logger.warning(
        "secret mismatch for client=%s",
        getattr(client, "client_id", "?"),
    )
    raise HTTPException(status_code=401, detail="invalid_client")


async def _base_client_auth(
    db: AsyncSession,
    request: Request,
    basic_creds: HTTPBasicCredentials | None = None,
    credentials: HTTPAuthorizationCredentials | None = None,
) -> AuthClient:
    """Authenticate client and return the persisted Client model."""
    client_id: str | None = None
    token: str | None = None

    scheme = credentials.scheme.lower() if credentials and credentials.scheme else ""
    cred = credentials.credentials if credentials else ""

    if scheme == "bearer" and cred:
        token = cred
        try:
            claims = jwt_payload_unverified(token) or {}
            client_id = claims.get("sub")
        except Exception as ex:
            logger.exception("Failed to decode bearer token: %s", ex)
            raise HTTPException(status_code=401, detail="invalid_client_assertion")
    elif basic_creds and basic_creds.username is not None:
        client_id = basic_creds.username
        token = basic_creds.password or ""
        scheme = "basic"
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorized",
            headers={"WWW-Authenticate": "Bearer, Basic"},
        )

    if not client_id or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorized",
            headers={"WWW-Authenticate": "Bearer, Basic"},
        )

    repo = ClientRepository(db)
    client = await repo.get_by_client_id(str(client_id))
    if client is None:
        logger.warning("unknown client_id=%s", client_id)
        raise HTTPException(status_code=401, detail="invalid_client")

    allowed = (client.client_auth_method or "").lower()
    if allowed not in set(CLIENT_AUTH_METHODS):
        logger.warning(
            "unsupported auth method=%s for client=%s",
            allowed,
            client.client_id,
        )
        raise HTTPException(status_code=401, detail="invalid_client")

    if allowed == CLIENT_AUTH_METHOD.CLIENT_SECRET_BASIC and scheme != "basic":
        logger.warning(
            "client=%s requires basic auth, got scheme=%s",
            client.client_id,
            scheme,
        )
        raise HTTPException(status_code=401, detail="invalid_client")
    if allowed == CLIENT_AUTH_METHOD.PRIVATE_KEY_JWT and scheme != "bearer":
        logger.warning(
            "client=%s requires private_key_jwt, got scheme=%s",
            client.client_id,
            scheme,
        )
        raise HTTPException(status_code=401, detail="invalid_client")

    if allowed == CLIENT_AUTH_METHOD.PRIVATE_KEY_JWT:
        await _authenticate_private_key_jwt(client, token, request, db)
        request.state.client_id = str(client.client_id)
        return client

    if allowed == CLIENT_AUTH_METHOD.CLIENT_SECRET_BASIC:
        _authenticate_client_secret_basic(client, token)
        request.state.client_id = str(client.client_id)
        return client

    raise HTTPException(status_code=401, detail="invalid_client")


async def client_auth(
    request: Request,
    basic_creds: HTTPBasicCredentials | None = Security(basic_security),
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_security),
    db: AsyncSession = Depends(get_db_session),
) -> AuthClient:
    """FastAPI dependency: authenticate client for tenant endpoints."""

    return await _base_client_auth(db, request, basic_creds, credentials)
