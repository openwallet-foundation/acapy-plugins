"""Crypto helpers (simple mode)."""

import base64
import os
import secrets

from authlib.jose import jwk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from admin.config import settings


def _b64url_decode_padded(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "===")


def _b64url_encode_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _load_key(version: int = 1) -> bytes | None:
    """Return key for version (v1 uses KEY_ENC_SECRET)."""
    secret = settings.KEY_ENC_SECRETS.get(str(version))
    if not secret:
        return None
    try:
        return _b64url_decode_padded(secret)
    except Exception:
        return None


def _aead_encrypt(plaintext: str) -> str:
    """AES-GCM encrypt with version prefix."""
    version = settings.KEY_ENC_VERSION or 1
    key = _load_key(version)
    if not key:
        return plaintext
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = _b64url_encode_no_pad(nonce + ct)
    # Always prefix with version, e.g., v1:... or v2:...
    return f"v{version}:{blob}"


def _aead_decrypt(blob: str) -> str:
    """AES-GCM decrypt with version prefix, assume v1 if missing."""
    version = 1
    b64_blob = blob
    if isinstance(blob, str) and blob.startswith("v") and ":" in blob[:6]:
        # Parse version prefix, e.g., v2:...
        vpart, b64_blob = blob.split(":", 1)
        try:
            version = int(vpart[1:])
        except Exception:
            version = 1
    key = _load_key(version)
    if not key:
        # fallback: if v1 and no key, return as plaintext
        return blob
    try:
        raw = _b64url_decode_padded(b64_blob)
    except Exception:
        return blob
    if len(raw) < 12 + 16:
        return blob
    nonce, ct_tag = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct_tag, None).decode("utf-8")
    except Exception:
        return blob


def encrypt_private_pem(private_pem: str) -> str:
    """Encrypt PEM with AES-GCM."""
    return _aead_encrypt(private_pem)


def decrypt_private_pem(private_pem_enc: str) -> str:
    """Decrypt PEM string."""
    return _aead_decrypt(private_pem_enc)


def encrypt_db_password(password: str) -> str:
    """Encrypt DB password."""
    return _aead_encrypt(password)


def decrypt_db_password(password_enc: str) -> str:
    """Decrypt DB password."""
    return _aead_decrypt(password_enc)


def generate_es256_keypair(kid: str | None = None, encrypt: bool = True) -> dict:
    """Generate ES256 keypair and return dict."""
    prv = ec.generate_private_key(ec.SECP256R1())
    private_pem = prv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_jwk = jwk.dumps(private_pem, kty="EC", crv="P-256", is_private=False)
    _kid = kid or f"as-{secrets.token_hex(4)}"
    public_jwk["kid"] = _kid
    public_jwk["alg"] = "ES256"
    public_jwk["use"] = "sig"

    private_pem_enc = encrypt_private_pem(private_pem) if encrypt else private_pem

    return {
        "kid": _kid,
        "alg": "ES256",
        "public_jwk": public_jwk,
        "private_pem_enc": private_pem_enc,
        "private_pem": private_pem,
    }
