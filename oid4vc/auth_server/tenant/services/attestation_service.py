"""Client attestation validation for tenant token flow."""

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from authlib.oauth2.rfc6749.errors import InvalidRequestError

from tenant.config import settings


class InvalidAttestationError(InvalidRequestError):
    """OAuth error for invalid client attestation."""

    error = "invalid_attestation"


class AttestationPolicyError(InvalidRequestError):
    """OAuth error for trust policy violations."""

    error = "invalid_request"


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _jwt_part(jwt_token: str, index: int) -> dict[str, Any]:
    parts = jwt_token.split(".")
    if len(parts) != 3:
        raise InvalidAttestationError(description="malformed_attestation")
    try:
        raw = _b64url_decode(parts[index])
        obj = json.loads(raw)
    except Exception as ex:
        raise InvalidAttestationError(description="malformed_attestation") from ex
    if not isinstance(obj, dict):
        raise InvalidAttestationError(description="malformed_attestation")
    return obj


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _normalized_jkt_from_attestation(claims: dict[str, Any]) -> str | None:
    jkt = claims.get("jkt")
    if isinstance(jkt, str) and jkt:
        return jkt
    cnf = claims.get("cnf")
    if isinstance(cnf, dict):
        cnf_jkt = cnf.get("jkt")
        if isinstance(cnf_jkt, str) and cnf_jkt:
            return cnf_jkt
    return None


def _required_claim_str(claims: dict[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise InvalidAttestationError(description=f"missing_{name}")
    return value


def _required_claim_int(claims: dict[str, Any], name: str) -> int:
    value = claims.get(name)
    if not isinstance(value, int):
        raise InvalidAttestationError(description=f"missing_{name}")
    return value


def _thumbprint_b64url(jwk: dict[str, Any]) -> str:
    kty = jwk.get("kty")
    if kty == "RSA":
        ordered = {"e": jwk.get("e"), "kty": kty, "n": jwk.get("n")}
    elif kty == "EC":
        ordered = {
            "crv": jwk.get("crv"),
            "kty": kty,
            "x": jwk.get("x"),
            "y": jwk.get("y"),
        }
    elif kty == "OKP":
        ordered = {"crv": jwk.get("crv"), "kty": kty, "x": jwk.get("x")}
    else:
        raise InvalidAttestationError(description="unsupported_jwk_kty")

    if any(
        not isinstance(ordered.get(key), str) or not ordered.get(key)
        for key in ordered
    ):
        raise InvalidAttestationError(description="invalid_dpop_jwk")

    canonical = json.dumps(ordered, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    digest = hashlib.sha256(canonical).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _extract_dpop_jkt(dpop_proof: str | None) -> str | None:
    if not dpop_proof:
        return None
    header = _jwt_part(dpop_proof, 0)
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise InvalidAttestationError(description="invalid_dpop_header")
    return _thumbprint_b64url(jwk)


def _matches_entry(entry: str, subject: str, jkt: str | None) -> bool:
    parts = [part.strip() for part in entry.split("|", 1)]
    if not parts or not parts[0]:
        return False
    entry_subject = parts[0]
    entry_jkt = parts[1] if len(parts) > 1 and parts[1] else None
    if entry_subject != subject:
        return False
    if entry_jkt is None:
        return True
    return entry_jkt == (jkt or "")


def _apply_policy(subject: str, jkt: str | None) -> tuple[str, str]:
    policy = settings.ATTESTATION_TRUST_POLICY

    if policy == "auto_trust":
        return policy, "trusted"

    if policy == "allow_list":
        allow_list = settings.ATTESTATION_ALLOW_LIST
        if any(_matches_entry(entry, subject, jkt) for entry in allow_list):
            return policy, "trusted"
        raise AttestationPolicyError(description="attestation_not_allowed")

    if policy == "deny_list":
        deny_list = settings.ATTESTATION_DENY_LIST
        if any(_matches_entry(entry, subject, jkt) for entry in deny_list):
            raise AttestationPolicyError(description="attestation_denied")
        return policy, "trusted"

    raise AttestationPolicyError(description="invalid_attestation_policy")


def validate_client_attestation(
    *,
    client_attestation: str | None,
    dpop_proof: str | None,
    attestation_required: bool,
) -> dict[str, Any] | None:
    """Validate optional/required client_attestation and return normalized metadata."""
    if not client_attestation:
        if attestation_required:
            raise InvalidAttestationError(description="missing_client_attestation")
        return None

    claims = _jwt_part(client_attestation, 1)
    issuer = _required_claim_str(claims, "iss")
    subject = _required_claim_str(claims, "sub")
    issued_at = _required_claim_int(claims, "iat")
    expires_at = _required_claim_int(claims, "exp")

    skew = int(settings.ATTESTATION_CLOCK_SKEW_SECONDS)
    now = _now_ts()
    if issued_at > now + skew:
        raise InvalidAttestationError(description="attestation_not_yet_valid")
    if expires_at <= now - skew:
        raise InvalidAttestationError(description="attestation_expired")

    attestation_jkt = _normalized_jkt_from_attestation(claims)
    dpop_jkt = _extract_dpop_jkt(dpop_proof)
    if settings.ATTESTATION_BIND_DPOP_JKT and attestation_jkt:
        if not dpop_jkt or dpop_jkt != attestation_jkt:
            raise InvalidAttestationError(description="attestation_dpop_mismatch")

    policy, decision = _apply_policy(subject, attestation_jkt)

    token_hash = hashlib.sha256(client_attestation.encode("utf-8")).hexdigest()
    return {
        "present": True,
        "verified": True,
        "policy": policy,
        "decision": decision,
        "iss": issuer,
        "sub": subject,
        "jkt": attestation_jkt,
        "iat": issued_at,
        "exp": expires_at,
        "hash": f"sha256:{token_hash}",
    }
