"""JOSE helpers for externally issued JWTs and DPoP proofs, built on PyJWT.

ACA-Py's ``jwt_verify`` resolves keys through the wallet and askar, which only
supports EdDSA and ES256. Tokens issued by an external authorization server
(e.g. Keycloak, RS256 by default) and DPoP proofs (any asymmetric algorithm)
need verification against a bare public JWK. PyJWT (a dependency of
``acapy-agent``) does the signature and registered-claim checks; this module
adds what PyJWT doesn't provide: algorithm/key policy, RFC 7638 thumbprints, an
async JWKS cache and a replay cache.
"""

import base64
import hashlib
import json
import logging
import time
from typing import Any, Iterable, Mapping

import jwt
from jwt.exceptions import (
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidSubjectError,
    PyJWTError,
)

LOGGER = logging.getLogger(__name__)

# Asymmetric JWS algorithms accepted for externally issued JWTs and proofs.
ASYMMETRIC_ALGS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)
HMAC_ALGS = frozenset({"HS256", "HS384", "HS512"})

# ESxxx requires a specific curve (RFC 7518 §3.4).
_EC_ALG_CURVE = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}

# JWK members that only appear in private keys.
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


class JoseError(ValueError):
    """Raised when a JWS cannot be parsed or verified."""


class JoseSignatureError(JoseError):
    """The signature does not verify."""


class JoseAudienceError(JoseError):
    """The ``aud`` claim does not match."""


class JoseIssuerError(JoseError):
    """The ``iss`` claim does not match."""


class JoseSubjectError(JoseError):
    """The ``sub`` claim does not match."""


def b64url_encode(value: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def unverified_header(token: str) -> dict:
    """Return the JWS header without verifying anything."""
    try:
        return jwt.get_unverified_header(token)
    except PyJWTError as err:
        raise JoseError(f"malformed JWS: {err}") from err


def unverified_claims(token: str) -> dict:
    """Return the JWT claims without verifying anything."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except PyJWTError as err:
        raise JoseError(f"malformed JWT: {err}") from err


def public_key(jwk: Mapping[str, Any], alg: str):
    """Load a public JWK for ``alg``, enforcing the algorithm/key policy."""
    if alg not in ASYMMETRIC_ALGS:
        raise JoseError(f"alg not allowed: {alg}")
    if alg in _EC_ALG_CURVE and jwk.get("crv") != _EC_ALG_CURVE[alg]:
        raise JoseError(f"{alg} requires curve {_EC_ALG_CURVE[alg]}")
    try:
        return jwt.PyJWK(dict(jwk), algorithm=alg).key
    except PyJWTError as err:
        raise JoseError(f"JWK unusable for {alg}: {err}") from err


def _decode(
    token: str,
    key: Any,
    alg: str,
    *,
    audience: str | None,
    issuer: str | None,
    subject: str | None,
    leeway: float,
    require: Iterable[str],
    verify_exp: bool,
) -> dict:
    try:
        return jwt.decode(
            token,
            key,
            algorithms=[alg],
            audience=audience,
            issuer=issuer,
            subject=subject,
            leeway=leeway,
            options={
                "require": list(require),
                "verify_aud": audience is not None,
                "verify_exp": verify_exp,
            },
        )
    except InvalidSignatureError as err:
        raise JoseSignatureError("invalid signature") from err
    except InvalidAudienceError as err:
        raise JoseAudienceError(str(err)) from err
    except InvalidIssuerError as err:
        raise JoseIssuerError(str(err)) from err
    except InvalidSubjectError as err:
        raise JoseSubjectError(str(err)) from err
    except PyJWTError as err:
        raise JoseError(str(err)) from err


def decode_jwt(
    token: str,
    jwk: Mapping[str, Any],
    *,
    allowed_algs: Iterable[str] = ASYMMETRIC_ALGS,
    audience: str | None = None,
    issuer: str | None = None,
    subject: str | None = None,
    leeway: float = 30,
    require: Iterable[str] = ("exp",),
    verify_exp: bool = True,
) -> tuple[dict, dict]:
    """Verify a JWT against a public JWK and validate its claims.

    Returns ``(header, claims)``. ``exp``/``nbf``/``iat`` are validated by
    PyJWT; ``aud``/``iss``/``sub`` only when given.
    """
    header = unverified_header(token)
    alg = header.get("alg")
    if alg not in allowed_algs:
        raise JoseError(f"alg not allowed: {alg}")
    claims = _decode(
        token,
        public_key(jwk, alg),
        alg,
        audience=audience,
        issuer=issuer,
        subject=subject,
        leeway=leeway,
        require=require,
        verify_exp=verify_exp,
    )
    return header, claims


def decode_hmac_jwt(
    token: str,
    secret: str,
    *,
    audience: str | None = None,
    issuer: str | None = None,
    subject: str | None = None,
    leeway: float = 30,
    require: Iterable[str] = ("exp",),
) -> dict:
    """Verify an HMAC-signed JWT (``client_secret_jwt``) and validate its claims."""
    alg = unverified_header(token).get("alg")
    if alg not in HMAC_ALGS:
        raise JoseError(f"alg not allowed: {alg}")
    return _decode(
        token,
        secret,
        alg,
        audience=audience,
        issuer=issuer,
        subject=subject,
        leeway=leeway,
        require=require,
        verify_exp=True,
    )


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """Compute the RFC 7638 SHA-256 JWK thumbprint (base64url)."""
    kty = jwk.get("kty")
    if kty == "RSA":
        members = ("e", "kty", "n")
    elif kty == "EC":
        members = ("crv", "kty", "x", "y")
    elif kty == "OKP":
        members = ("crv", "kty", "x")
    else:
        raise JoseError(f"unsupported JWK kty: {kty}")
    try:
        canonical = {m: jwk[m] for m in members}
    except KeyError as err:
        raise JoseError(f"JWK missing required member {err}") from err
    data = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
    return b64url_encode(hashlib.sha256(data).digest())


class JWKSCache:
    """Small async JWKS cache keyed by JWKS URI.

    Keys are refetched after ``ttl`` seconds, or immediately (rate limited) when
    a token references an unknown ``kid`` to pick up key rotation. (PyJWT's
    ``PyJWKClient`` is synchronous, so it can't be used on the event loop.)
    """

    def __init__(self, ttl: int = 300, min_refresh_interval: int = 10):
        """Initialize the cache."""
        self.ttl = ttl
        self.min_refresh_interval = min_refresh_interval
        self._entries: dict[str, tuple[float, list[dict]]] = {}

    async def _fetch(self, jwks_uri: str) -> list[dict]:
        from .app_resources import AppResources  # noqa: PLC0415

        resp = await AppResources.get_http_client().get(jwks_uri)
        if resp.status != 200:
            raise JoseError(f"JWKS fetch from {jwks_uri} failed: HTTP {resp.status}")
        body = await resp.json(content_type=None)
        keys = body.get("keys") if isinstance(body, dict) else None
        if not isinstance(keys, list):
            raise JoseError(f"JWKS at {jwks_uri} has no keys")
        self._entries[jwks_uri] = (time.monotonic(), keys)
        return keys

    @staticmethod
    def _select(keys: list[dict], kid: str | None, alg: str | None) -> dict | None:
        candidates = [
            k
            for k in keys
            if k.get("use", "sig") == "sig"
            and (kid is None or k.get("kid") == kid)
            and (alg is None or k.get("alg") in (None, alg))
        ]
        if not candidates or (kid is None and len(candidates) > 1):
            return None
        return candidates[0]

    async def get_key(self, jwks_uri: str, kid: str | None, alg: str | None) -> dict:
        """Return the JWK for ``kid`` from ``jwks_uri``."""
        entry = self._entries.get(jwks_uri)
        now = time.monotonic()
        fetched = entry is None or now - entry[0] > self.ttl
        keys = await self._fetch(jwks_uri) if fetched else entry[1]
        key = self._select(keys, kid, alg)
        if key is None and not fetched and now - entry[0] > self.min_refresh_interval:
            # Unknown kid in a cached set: refetch (rate limited) to pick up rotation.
            key = self._select(await self._fetch(jwks_uri), kid, alg)
        if key is None:
            raise JoseError(f"no matching key in JWKS for kid {kid!r}")
        return key

    async def decode(self, jwks_uri: str, token: str, **kwargs) -> tuple[dict, dict]:
        """Verify ``token`` against the JWKS at ``jwks_uri``; see ``decode_jwt``."""
        header = unverified_header(token)
        key = await self.get_key(jwks_uri, header.get("kid"), header.get("alg"))
        return decode_jwt(token, key, **kwargs)


class ReplayCache:
    """In-memory single-use identifier cache (per process).

    Deployments with several plugin instances behind a load balancer need
    shared storage for full replay protection; within one instance this is exact
    as long as fewer than ``max_entries`` identifiers are live at once: beyond
    that the oldest entries (the ones closest to expiry) are evicted.
    """

    def __init__(self, max_entries: int = 100_000, min_prune_interval: float = 1.0):
        """Initialize the cache."""
        self.max_entries = max_entries
        self.min_prune_interval = min_prune_interval
        self._seen: dict[str, float] = {}  # insertion ordered
        self._next_prune = 0.0

    def check_and_add(self, value: str, expires_at: float) -> bool:
        """Record ``value``; return False if it was already seen and not expired."""
        now = time.time()
        seen_until = self._seen.get(value)
        if seen_until is not None and seen_until > now:
            return False
        if len(self._seen) >= self.max_entries:
            self._make_room(now)
        self._seen[value] = expires_at
        return True

    def _make_room(self, now: float) -> None:
        # A full scan for expired entries at most every min_prune_interval
        # seconds; if the cache is still full, evict the oldest entries.
        if now >= self._next_prune:
            self._seen = {k: v for k, v in self._seen.items() if v > now}
            self._next_prune = now + self.min_prune_interval
        while len(self._seen) >= self.max_entries:
            del self._seen[next(iter(self._seen))]
