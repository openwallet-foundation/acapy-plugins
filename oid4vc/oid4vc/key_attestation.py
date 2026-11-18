"""Verify OID4VCI Key Attestations (Appendix D.1) sent as `attestation` proofs (F.3)."""

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from acapy_agent.core.profile import Profile
from acapy_agent.wallet.jwt import b64_to_dict
from acapy_agent.wallet.util import b64_to_bytes
from aries_askar import AskarError, Key, KeyAlg
from aiohttp import ClientError

from .jose_util import JWKSCache, JoseError, PRIVATE_JWK_MEMBERS
from .models.wallet_provider import WalletProvider
from .utils import get_issuer_configuration

KEY_ATTESTATION_TYP = "key-attestation+jwt"
CLOCK_SKEW = 60
LOGGER = logging.getLogger(__name__)
JWKS_CACHE = JWKSCache(ttl=300, min_refresh_interval=60)

PUBLIC_JWK_MEMBERS = {
    "EC": ("kty", "crv", "x", "y"),
    "OKP": ("kty", "crv", "x"),
}
# JWS algorithm for each key type Askar signs and verifies with
SIGNING_KEY_ALGS = {
    KeyAlg.P256: "ES256",
    KeyAlg.P384: "ES384",
    KeyAlg.K256: "ES256K",
    KeyAlg.ED25519: "EdDSA",
}


class KeyAttestationError(Exception):
    """Key Attestation rejected; `error` is an OID4VCI §8.3.1.2 error code."""

    def __init__(self, error: str, description: str):
        """Initialize the error."""
        super().__init__(description)
        self.error = error
        self.description = description


def _invalid(description: str) -> KeyAttestationError:
    return KeyAttestationError("invalid_proof", description)


def _signing_key(jwk: Mapping[str, Any]) -> tuple[dict[str, Any], Key]:
    if PRIVATE_JWK_MEMBERS & jwk.keys():
        raise ValueError("JWK contains private key members")
    kty = jwk.get("kty")
    members = PUBLIC_JWK_MEMBERS.get(kty) if isinstance(kty, str) else None
    if not members or any(not isinstance(jwk.get(m), str) for m in members):
        raise ValueError("unsupported or incomplete JWK")
    public = {m: jwk[m] for m in members}
    try:
        key = Key.from_jwk(json.dumps(public))
    except AskarError as err:
        raise ValueError("unsupported or invalid JWK") from err
    if key.algorithm not in SIGNING_KEY_ALGS:
        raise ValueError("JWK is not a supported signing key")
    return public, key


def public_jwk(jwk: Mapping[str, Any]) -> dict[str, Any]:
    """Return the public members of a public signing JWK, else raise ValueError."""
    return _signing_key(jwk)[0]


def signing_alg(jwk: Mapping[str, Any]) -> str:
    """Return the JWS algorithm for `jwk`'s key type; raises like `public_jwk`."""
    return SIGNING_KEY_ALGS[_signing_key(jwk)[1].algorithm]


@dataclass
class KeyAttestationResult:
    """A verified Key Attestation."""

    iss: str
    kid: str
    attested_keys: list[dict[str, Any]]
    nonce: str
    key_storage: list[str] = field(default_factory=list)
    user_authentication: list[str] = field(default_factory=list)


async def resolve_signer_key(
    profile: Profile, iss: str, kid: str, alg: str
) -> Optional[dict[str, Any]]:
    """Find the key for `iss` and `kid`; JWKS network and JSON errors propagate."""
    async with profile.session() as session:
        providers = await WalletProvider.query(session, {"iss": iss, "active": "True"})
    for provider in providers:
        if provider.jwks:
            # Same selection rules as JWKSCache uses for jwks_uri keys
            key = next(
                (
                    key
                    for key in provider.jwks.get("keys", [])
                    if key.get("kid") == kid
                    and key.get("use", "sig") == "sig"
                    and key.get("alg") in (None, alg)
                ),
                None,
            )
            if key:
                return key
        elif provider.jwks_uri:
            try:
                return await JWKS_CACHE.get_key(provider.jwks_uri, kid, alg)
            except JoseError as err:
                LOGGER.info(
                    "Wallet Provider JWKS lookup rejected: iss=%s kid=%s reason=%s",
                    iss,
                    kid,
                    err,
                )
    return None


def _string_list(payload: Mapping[str, Any], claim: str) -> list[str]:
    value = payload.get(claim)
    if value is None:
        return []
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(v, str) for v in value)
    ):
        raise _invalid(f"{claim} must be a non-empty array of strings")
    return value


def _int_claim(payload: Mapping[str, Any], claim: str) -> int:
    value = payload.get(claim)
    if not isinstance(value, int) or isinstance(value, bool):
        raise _invalid(f"{claim} is required and must be an integer")
    return value


async def verify_key_attestation(
    profile: Profile, token: str, proof_metadata: Mapping[str, Any]
) -> KeyAttestationResult:
    """Verify an `attestation` proof JWT; the caller redeems the returned nonce."""
    if not isinstance(token, str) or token.count(".") != 2:
        raise _invalid("key attestation is not a compact JWS")
    encoded_header, encoded_payload, encoded_signature = token.split(".")
    try:
        headers = b64_to_dict(encoded_header)
        payload = b64_to_dict(encoded_payload)
        signature = b64_to_bytes(encoded_signature, urlsafe=True)
    except (ValueError, TypeError) as err:
        raise _invalid("key attestation is not a valid JWT") from err
    if not isinstance(headers, dict) or not isinstance(payload, dict):
        raise _invalid("key attestation is not a valid JWT")

    if headers.get("typ") != KEY_ATTESTATION_TYP:
        raise _invalid(f"typ must be {KEY_ATTESTATION_TYP}")
    alg = headers.get("alg")
    allowed_algs = proof_metadata.get("proof_signing_alg_values_supported") or []
    if not isinstance(alg, str) or alg not in allowed_algs:
        raise _invalid("alg is not supported for the attestation proof type")

    iss = payload.get("iss")
    kid = headers.get("kid")
    if not isinstance(iss, str) or not iss:
        raise _invalid("iss is required")
    if not isinstance(kid, str) or not kid:
        raise _invalid("kid header is required")

    try:
        signer_jwk = await resolve_signer_key(profile, iss, kid, alg)
    except (ClientError, TimeoutError, ValueError) as err:
        raise KeyAttestationError(
            "credential_request_denied", "Wallet Provider keys are unavailable"
        ) from err
    if signer_jwk is None:
        raise _invalid("key attestation signer is not trusted")
    try:
        signer_key = _signing_key(signer_jwk)[1]
        verified = signer_key.verify_signature(
            f"{encoded_header}.{encoded_payload}".encode(), signature, sig_type=alg
        )
    except Exception as err:
        raise _invalid("key attestation signature could not be verified") from err
    if not verified:
        raise _invalid("key attestation signature is invalid")

    now = int(time.time())
    if _int_claim(payload, "iat") > now + CLOCK_SKEW:
        raise _invalid("iat is in the future")
    if _int_claim(payload, "exp") + CLOCK_SKEW < now:
        raise _invalid("key attestation has expired")

    attested_keys = payload.get("attested_keys")
    if not isinstance(attested_keys, list) or not attested_keys:
        raise _invalid("attested_keys must be a non-empty array")
    async with profile.session() as session:
        issuer_config = await get_issuer_configuration(session, profile)
    batch_issuance = issuer_config.batch_credential_issuance if issuer_config else None
    # Wallets learn the limit from the published batch_size; without it, one key
    limit = (batch_issuance or {}).get("batch_size") or 1
    if len(attested_keys) > limit:
        raise KeyAttestationError(
            "invalid_credential_request", f"attested_keys exceeds the limit of {limit}"
        )
    public_keys: list[dict[str, Any]] = []
    seen: set[str] = set()
    for attested_key in attested_keys:
        if not isinstance(attested_key, dict):
            raise _invalid("attested_keys entries must be JWKs")
        try:
            public_key = public_jwk(attested_key)
        except ValueError as err:
            raise _invalid(f"attested key rejected: {err}") from err
        identity = json.dumps(public_key, sort_keys=True)
        if identity in seen:
            raise _invalid("attested_keys must not contain duplicate keys")
        seen.add(identity)
        public_keys.append(public_key)

    key_storage = _string_list(payload, "key_storage")
    user_authentication = _string_list(payload, "user_authentication")
    if "certification" in payload and not isinstance(payload["certification"], str):
        raise _invalid("certification must be a string")
    if "status" in payload and not isinstance(payload["status"], dict):
        raise _invalid("status must be an object")
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise _invalid("nonce is required")

    required = proof_metadata.get("key_attestations_required")
    if isinstance(required, dict):
        for claim, values in (
            ("key_storage", key_storage),
            ("user_authentication", user_authentication),
        ):
            accepted = required.get(claim)
            if accepted and not set(values) & set(accepted):
                raise _invalid(f"{claim} does not meet key_attestations_required")

    return KeyAttestationResult(
        iss=iss,
        kid=kid,
        attested_keys=public_keys,
        nonce=nonce,
        key_storage=key_storage,
        user_authentication=user_authentication,
    )
