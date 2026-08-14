"""Crypto helpers (simple mode)."""

import os
import secrets

from joserfc.jwk import ECKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from admin.config import settings
from core.utils.encoding import b64url_decode, b64url_encode


def _load_key(version: int = 1) -> bytes | None:
    """Return key for version (v1 uses KEY_ENC_SECRET)."""
    secret = settings.KEY_ENC_SECRETS.get(str(version))
    if not secret:
        return None
    try:
        return b64url_decode(secret)
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
    blob = b64url_encode(nonce + ct)
    # Always prefix with version, e.g., v1:... or v2:...
    return f"v{version}:{blob}"


def _aead_decrypt(blob: str) -> str:
    """AES-GCM decrypt with version prefix, assume v1 if missing."""
    version = 1
    b64_blob = blob
    has_version_prefix = False
    if isinstance(blob, str) and blob.startswith("v") and ":" in blob[:6]:
        has_version_prefix = True
        # Parse version prefix, e.g., v2:...
        vpart, b64_blob = blob.split(":", 1)
        try:
            version = int(vpart[1:])
        except Exception:
            version = 1
    key = _load_key(version)
    if not key:
        if has_version_prefix:
            raise ValueError("decryption key unavailable for version %d" % version)
        # No version prefix and no key — treat as unencrypted plaintext
        return blob
    try:
        raw = b64url_decode(b64_blob)
    except Exception as exc:
        if has_version_prefix:
            raise ValueError("failed to decode encrypted blob") from exc
        return blob
    if len(raw) < 12 + 16:
        if has_version_prefix:
            raise ValueError("encrypted blob too short")
        return blob
    nonce, ct_tag = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct_tag, None).decode("utf-8")
    except Exception as exc:
        if has_version_prefix:
            raise ValueError("AEAD decryption failed") from exc
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

    public_jwk = ECKey.import_key(private_pem).as_dict(private=False)
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
    }
