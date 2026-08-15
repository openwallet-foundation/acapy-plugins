"""Minimal PBKDF2 helpers for hashing and verifying shared secrets."""

import hashlib
import hmac
import os
from typing import Tuple

from core.consts import PBKDF2_ALLOWED_ALGOS
from core.utils.encoding import b64url_decode, b64url_encode


def hash_secret_pbkdf2(
    secret: str,
    *,
    algo: str = "sha256",
    iterations: int = 100_000,
    salt_len: int = 16,
    dklen: int = 32,
) -> str:
    """Hash a secret with PBKDF2-HMAC and embed parameters."""
    if not isinstance(secret, str) or secret == "":
        raise ValueError("secret must be a non-empty string")
    salt = os.urandom(salt_len)
    dk = hashlib.pbkdf2_hmac(algo, secret.encode("utf-8"), salt, iterations, dklen)
    return f"pbkdf2:{algo}:{iterations}$%s$%s" % (
        b64url_encode(salt),
        b64url_encode(dk),
    )


def _parse_pbkdf2(encoded: str) -> Tuple[str, int, bytes, bytes]:
    # Format: pbkdf2:<algo>:<iterations>$<salt_b64url>$<hash_b64url>
    try:
        prefix, rest = encoded.split(":", 1)
        if prefix != "pbkdf2":
            raise ValueError
        algo, rest2 = rest.split(":", 1)
        iter_s, salt_b64, hash_b64 = rest2.split("$")
        iterations = int(iter_s)
        salt = b64url_decode(salt_b64)
        dk = b64url_decode(hash_b64)
        return algo, iterations, salt, dk
    except Exception as ex:
        raise ValueError("invalid pbkdf2 format") from ex


def verify_secret_pbkdf2(secret: str, encoded: str) -> bool:
    """Verify a PBKDF2-HMAC hash string produced by hash_secret_pbkdf2."""
    try:
        algo, iterations, salt, expected = _parse_pbkdf2(encoded)
        if algo not in PBKDF2_ALLOWED_ALGOS:
            return False
        if iterations > 1_000_000:
            return False
        dklen = len(expected)
        actual = hashlib.pbkdf2_hmac(
            algo, secret.encode("utf-8"), salt, iterations, dklen
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False
