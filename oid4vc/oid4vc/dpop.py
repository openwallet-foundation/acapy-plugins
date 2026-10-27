"""DPoP proof verification (RFC 9449).

Used by the built-in token endpoint (to bind issued tokens to the wallet key)
and by the resource-server side (``/credential``, ``/notification``) for any
access token carrying ``cnf.jkt``, whichever authorization server issued it.

Not implemented: server-provided ``DPoP-Nonce`` (RFC 9449 §8/§9).
"""

import base64
import hashlib
import time
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

from .jose_util import (
    ASYMMETRIC_ALGS,
    PRIVATE_JWK_MEMBERS,
    JoseError,
    JoseSignatureError,
    ReplayCache,
    decode_jwt,
    jwk_thumbprint,
    unverified_header,
)

DPOP_HEADER = "DPoP"
DPOP_TYP = "dpop+jwt"

# Proofs older than this (seconds) are rejected; iat in the future is allowed
# up to LEEWAY to tolerate clock skew.
DEFAULT_MAX_AGE = 300
DEFAULT_LEEWAY = 60

_JTI_CACHE = ReplayCache()


class DPoPError(Exception):
    """A DPoP proof is missing or invalid."""

    def __init__(self, description: str, error: str = "invalid_dpop_proof"):
        """Initialize the error."""
        super().__init__(description)
        self.error = error
        self.description = description


def normalize_htu(url: str) -> str:
    """Normalize a URL for htu comparison (RFC 9449 §4.3 / RFC 3986 §6).

    Drops query and fragment, lowercases scheme and host, removes default
    ports and a trailing slash.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    if port and not (
        (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    ):
        host = f"{host}:{port}"
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((scheme, host, path, "", ""))


def access_token_hash(access_token: str) -> str:
    """Return the ``ath`` value for an access token."""
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify_dpop_proof(
    proof: str | None,
    *,
    htm: str,
    htu: str | Iterable[str],
    access_token: str | None = None,
    expected_jkt: str | None = None,
    max_age: int = DEFAULT_MAX_AGE,
    leeway: int = DEFAULT_LEEWAY,
) -> str:
    """Verify a DPoP proof JWT and return the JWK thumbprint of its key.

    Args:
        proof: value of the ``DPoP`` request header
        htm: HTTP method of the request
        htu: the public URL of the request (as the client addressed it), or
            the acceptable URLs when the request can be reached under several
        access_token: when presenting a token to a resource server, the token;
            ``ath`` is then required and checked
        expected_jkt: ``cnf.jkt`` of the access token, if bound
        max_age: maximum proof age in seconds
        leeway: allowed clock skew for ``iat`` in the future
    """
    if not proof:
        raise DPoPError("DPoP proof is missing")
    if "," in proof:
        raise DPoPError("multiple DPoP proofs")
    try:
        header = unverified_header(proof)
    except JoseError as err:
        raise DPoPError(f"malformed DPoP proof: {err}") from err

    if header.get("typ") != DPOP_TYP:
        raise DPoPError(f"DPoP proof typ must be {DPOP_TYP}")
    alg = header.get("alg")
    if alg not in ASYMMETRIC_ALGS:
        raise DPoPError(f"unsupported DPoP proof alg: {alg}")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise DPoPError("DPoP proof header has no jwk")
    if PRIVATE_JWK_MEMBERS.intersection(jwk):
        raise DPoPError("DPoP proof jwk must not contain a private key")
    try:
        thumbprint = jwk_thumbprint(jwk)
        # Signature, presence of the required claims and iat not in the future
        # (beyond leeway); proofs have no exp.
        _, payload = decode_jwt(
            proof,
            jwk,
            require=("jti", "htm", "htu", "iat"),
            verify_exp=False,
            leeway=leeway,
        )
    except JoseSignatureError as err:
        raise DPoPError("DPoP proof signature is invalid") from err
    except JoseError as err:
        raise DPoPError(f"DPoP proof is invalid: {err}") from err

    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise DPoPError("DPoP proof has no jti")
    if payload.get("htm") != htm.upper():
        raise DPoPError("DPoP proof htm does not match the request method")
    proof_htu = payload.get("htu")
    accepted = [htu] if isinstance(htu, str) else list(htu)
    try:
        htu_matches = isinstance(proof_htu, str) and normalize_htu(proof_htu) in {
            normalize_htu(url) for url in accepted
        }
    except ValueError:  # the proof's htu is not a parsable URL
        htu_matches = False
    if not htu_matches:
        raise DPoPError("DPoP proof htu does not match the request URL")
    iat = payload.get("iat")
    now = time.time()
    if not isinstance(iat, (int, float)):
        raise DPoPError("DPoP proof has no iat")
    if iat > now + leeway or iat < now - max_age:
        raise DPoPError("DPoP proof iat is outside the acceptable window")

    if access_token is not None:
        if payload.get("ath") != access_token_hash(access_token):
            raise DPoPError("DPoP proof ath does not match the access token")
    if expected_jkt is not None and thumbprint != expected_jkt:
        raise DPoPError(
            "DPoP proof key does not match the access token binding",
            error="invalid_token",
        )

    # Record the jti last so a rejected proof doesn't burn a valid one.
    if not _JTI_CACHE.check_and_add(f"{thumbprint}:{jti}", iat + max_age + leeway):
        raise DPoPError("DPoP proof jti has already been used")
    return thumbprint
