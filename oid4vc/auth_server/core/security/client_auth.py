"""Client authentication for issuer APIs."""

import json
from typing import Any, Mapping

import httpx
from authlib.jose import JsonWebKey, jwt
from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasicCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from core.consts import CLIENT_AUTH_METHODS
from core.consts import ClientAuthMethod as CLIENT_AUTH_METHOD
from core.crypto.crypto import verify_secret_pbkdf2
from core.models import Client as AuthClient
from core.repositories.client_repository import ClientRepository
from core.security.utils import jwt_header_unverified, jwt_payload_unverified
from core.utils.logging import get_logger

logger = get_logger(__name__)


async def _load_jwks(client) -> dict | None:
    if isinstance(client.jwks, dict):
        return client.jwks
    if client.jwks and isinstance(client.jwks, str):
        try:
            return json.loads(client.jwks)
        except Exception:
            return None
    if client.jwks_uri:
        try:
            async with httpx.AsyncClient(timeout=5.0) as h:
                r = await h.get(client.jwks_uri)
                r.raise_for_status()
                data = r.json()
                return data if isinstance(data, dict) else None
        except Exception:
            return None
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
    for claim in ("iss", "sub", "aud", "exp", "iat"):
        if claim not in decoded:
            raise HTTPException(status_code=401, detail=f"missing_{claim}")
    aud = decoded.get("aud")
    expected_aud = _audiences_for(request)
    if isinstance(aud, str):
        aud = [aud]
    if not aud or not any(a in expected_aud for a in aud):
        raise HTTPException(status_code=401, detail="invalid_audience")


def _decode_and_validate_jwt(
    token: str,
    key_material: Any,
    request: Request,
    expected_alg: str | None = None,
) -> Mapping[str, Any]:
    """Decode, validate, and return JWT claims using provided key material."""

    if expected_alg:
        _validate_jwt_alg(token, expected_alg)

    try:
        claims = jwt.decode(token, key_material)  # type: ignore[arg-type]
        claims.validate(now=None, leeway=30)
        _validate_jwt_claims(claims, request)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="invalid_client_assertion") from exc

    if not isinstance(claims, Mapping):
        raise HTTPException(status_code=401, detail="invalid_client_assertion")

    return claims


async def _authenticate_private_key_jwt(
    client: AuthClient, token: str, request: Request
) -> Mapping[str, Any]:
    """Validate private_key_jwt assertions."""

    jwks = await _load_jwks(client)
    if not isinstance(jwks, dict) or not jwks.get("keys"):
        raise HTTPException(status_code=401, detail="invalid_client_keys")

    keys = JsonWebKey.import_key_set(jwks)
    return _decode_and_validate_jwt(
        token,
        keys,
        request,
        expected_alg=client.client_auth_signing_alg,
    )


async def _authenticate_shared_key_jwt(
    client: AuthClient, token: str, request: Request, presented_client_id: str
) -> Mapping[str, Any]:
    """Validate shared_key_jwt assertions signed with a shared secret."""

    secret = client.client_secret or ""
    if not secret:
        raise HTTPException(status_code=401, detail="unauthorized_client")

    claims = _decode_and_validate_jwt(
        token,
        secret,
        request,
        expected_alg=client.client_auth_signing_alg,
    )

    if str(claims.get("sub")) != str(presented_client_id):
        raise HTTPException(status_code=401, detail="invalid_client")

    return claims


def _authenticate_client_secret_basic(client: AuthClient, token: str) -> None:
    """Validate client_secret_basic credentials."""

    secret_hash = client.client_secret
    if secret_hash and token and verify_secret_pbkdf2(token, secret_hash):
        return
    raise HTTPException(status_code=401, detail="invalid_client")


async def base_client_auth(
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
        raise HTTPException(status_code=401, detail="invalid_client")

    allowed = (client.client_auth_method or "").lower()
    if allowed not in set(CLIENT_AUTH_METHODS):
        raise HTTPException(status_code=401, detail="unauthorized_client")

    if allowed == CLIENT_AUTH_METHOD.CLIENT_SECRET_BASIC and scheme != "basic":
        raise HTTPException(status_code=401, detail="unauthorized_client")
    if (
        allowed in {CLIENT_AUTH_METHOD.PRIVATE_KEY_JWT, CLIENT_AUTH_METHOD.SHARED_KEY_JWT}
        and scheme != "bearer"
    ):
        raise HTTPException(status_code=401, detail="unauthorized_client")

    if allowed == CLIENT_AUTH_METHOD.PRIVATE_KEY_JWT:
        await _authenticate_private_key_jwt(client, token, request)
        request.state.client_id = str(client.client_id)
        return client

    if allowed == CLIENT_AUTH_METHOD.SHARED_KEY_JWT:
        await _authenticate_shared_key_jwt(client, token, request, str(client_id))
        request.state.client_id = str(client.client_id)
        return client

    if allowed == CLIENT_AUTH_METHOD.CLIENT_SECRET_BASIC:
        _authenticate_client_secret_basic(client, token)
        request.state.client_id = str(client.client_id)
        return client

    raise HTTPException(status_code=401, detail="unauthorized_client")
