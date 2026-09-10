"""Client attestation validation for tenant token flow.

Verifies attestation JWTs signed by trusted Wallet Providers.
Provider public keys are looked up from the admin allow list via internal API.
"""

import json
from datetime import datetime, timezone
from typing import Any

import httpx
from authlib.oauth2.rfc6749.errors import InvalidRequestError
from joserfc import jwk, jwt
from joserfc.jws import extract_compact

from core.observability.observability import internal_api_headers
from core.consts import SUPPORTED_SIGNING_ALGS
from tenant.security.jti_cache import JtiCache
from core.utils.logging import get_logger
from tenant.config import settings

logger = get_logger(__name__)


# --- Attestation PoP jti replay cache (draft-07 §9 step 10) ---
_attest_pop_jti_cache = JtiCache()


def _jti_window() -> int:
    """Replay window for PoP jti values, read live so overrides take effect."""
    return int(settings.ATTESTATION_CLOCK_SKEW_SECONDS) * 2


class InvalidAttestationError(InvalidRequestError):
    """OAuth error for invalid client attestation."""

    error = "invalid_client_attestation"


class AttestationLookupError(Exception):
    """Provider lookup could not be completed; not a client error."""


def _jwt_extract(jwt_token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract JWT header and payload without signature verification."""
    try:
        obj = extract_compact(jwt_token.encode())
        header = obj.headers()
        payload = json.loads(obj.payload)
    except Exception as ex:
        logger.debug(
            "Attestation JWT extract failed: %s (token_len=%d)",
            ex,
            len(jwt_token),
            exc_info=True,
        )
        raise InvalidAttestationError(description="malformed_attestation") from ex
    if not isinstance(header, dict) or not isinstance(payload, dict):
        logger.debug(
            "Attestation JWT extract produced non-dict parts: "
            "header_type=%s payload_type=%s",
            type(header).__name__,
            type(payload).__name__,
        )
        raise InvalidAttestationError(description="malformed_attestation")
    return header, payload


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _required_claim_str(claims: dict[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        logger.debug(
            "Attestation claim %r missing/invalid: type=%s",
            name,
            type(value).__name__,
        )
        raise InvalidAttestationError(description=f"missing_{name}")
    return value


def _required_claim_int(claims: dict[str, Any], name: str) -> int:
    value = claims.get(name)
    if not isinstance(value, int):
        logger.debug(
            "Attestation claim %r missing/invalid: type=%s",
            name,
            type(value).__name__,
        )
        raise InvalidAttestationError(description=f"missing_{name}")
    return value


def _thumbprint(jwk_dict: dict[str, Any]) -> str:
    """Compute JWK thumbprint per RFC 7638 using joserfc."""
    try:
        return jwk.thumbprint(jwk_dict)
    except Exception as ex:
        logger.debug(
            "JWK thumbprint computation failed: %s (kty=%s, crv=%s)",
            ex,
            jwk_dict.get("kty"),
            jwk_dict.get("crv"),
            exc_info=True,
        )
        raise InvalidAttestationError(description="invalid_jwk") from ex


def _extract_cnf_jwk(claims: dict[str, Any]) -> dict[str, Any] | None:
    """Extract cnf.jwk from attestation payload."""
    cnf = claims.get("cnf")
    if not isinstance(cnf, dict):
        return None
    cnf_key = cnf.get("jwk")
    if isinstance(cnf_key, dict):
        return cnf_key
    return None


async def _lookup_provider_key(
    iss: str, kid: str | None = None
) -> dict[str, Any] | list[dict[str, Any]] | None:
    """Look up provider key(s) from admin internal API.

    When *kid* is provided, returns a single JWK dict.
    When *kid* is absent, returns a list of JWK dicts for trial verification.
    """
    url = f"{settings.INTERNAL_BASE_URL}/wallet-providers/lookup"
    headers = internal_api_headers(settings.INTERNAL_AUTH_TOKEN)
    params: dict[str, str] = {"iss": iss}
    if kid:
        params["kid"] = kid
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code != 200:
                logger.debug(
                    "Provider lookup non-200 iss=%s kid=%s status=%d",
                    iss,
                    kid,
                    resp.status_code,
                )
                raise AttestationLookupError(f"lookup status {resp.status_code}")
            data = resp.json()
            if not data.get("found"):
                logger.debug("Provider lookup not found iss=%s kid=%s", iss, kid)
                return None
            # Single key when kid was specified
            if kid:
                logger.debug("Provider lookup hit iss=%s kid=%s (single key)", iss, kid)
                return data.get("public_key")
            # All keys when kid was absent
            keys = data.get("keys") or []
            logger.debug(
                "Provider lookup hit iss=%s (no kid, %d keys for trial)",
                iss,
                len(keys) if isinstance(keys, list) else -1,
            )
            return keys
    except AttestationLookupError:
        raise
    except Exception as ex:
        logger.warning(
            "Failed to look up provider key iss=%s kid=%s",
            iss,
            kid,
            exc_info=True,
        )
        raise AttestationLookupError("provider lookup failed") from ex


def _verify_signature(
    token: str,
    public_key_jwk: dict[str, Any] | list[dict[str, Any]],
    *,
    error: str = "attestation_signature_invalid",
) -> dict[str, Any]:
    """Verify JWT signature. Accepts a single JWK or list for trial."""
    # joserfc KeySet lookup requires a `kid`; draft-07 5.1 makes it optional,
    # so unlabelled keys are tried one by one.
    if isinstance(public_key_jwk, list):
        for candidate in public_key_jwk:
            try:
                key = jwk.import_key(candidate)
                result = jwt.decode(token, key, algorithms=list(SUPPORTED_SIGNING_ALGS))
                return dict(result.claims)
            except Exception:
                continue
        logger.debug(
            "Signature verification failed (%s): trial keys n=%d, algs=%s",
            error,
            len(public_key_jwk),
            list(SUPPORTED_SIGNING_ALGS),
        )
        raise InvalidAttestationError(description=error)

    try:
        key = jwk.import_key(public_key_jwk)
        result = jwt.decode(token, key, algorithms=list(SUPPORTED_SIGNING_ALGS))
        return dict(result.claims)
    except Exception as ex:
        logger.debug(
            "Signature verification failed (%s): %s [kty=%s kid=%s crv=%s, algs=%s]",
            error,
            ex,
            public_key_jwk.get("kty"),
            public_key_jwk.get("kid"),
            public_key_jwk.get("crv"),
            list(SUPPORTED_SIGNING_ALGS),
            exc_info=True,
        )
        raise InvalidAttestationError(description=error) from ex


async def validate_client_attestation(
    *,
    client_attestation: str | None,
    client_attestation_pop: str | None = None,
    attestation_required: bool,
    expected_audience: str,
    db=None,
) -> dict[str, Any] | None:
    """Validate client attestation JWT + PoP against the trusted provider allow list.

    Implements draft-ietf-oauth-attestation-based-client-auth-07 §6.2 and §9.
    """
    if not client_attestation:
        # draft-07 9 step 1: a PoP without its attestation is a malformed request.
        if client_attestation_pop:
            logger.debug("Attestation PoP present without attestation header")
            raise InvalidAttestationError(description="missing_client_attestation")
        if attestation_required:
            logger.debug("Attestation required but missing")
            raise InvalidAttestationError(description="missing_client_attestation")
        return None

    logger.debug(
        "Validating client attestation (attestation_len=%d, pop_present=%s, "
        "expected_audience=%s, attestation_required=%s)",
        len(client_attestation),
        bool(client_attestation_pop),
        expected_audience,
        attestation_required,
    )

    # --- Attestation JWT validation (§5.1, §9 steps 2-6) ---

    # 1. Decode header and payload (without verification first, to extract iss + kid)
    header, claims = _jwt_extract(client_attestation)
    logger.debug(
        "Attestation header: typ=%s alg=%s kid=%s | claims keys=%s",
        header.get("typ"),
        header.get("alg"),
        header.get("kid"),
        sorted(claims.keys()),
    )

    # 2. Validate typ header (§5.1: REQUIRED, MUST be "oauth-client-attestation+jwt")
    typ = header.get("typ")
    if typ != "oauth-client-attestation+jwt":
        logger.debug("Attestation typ mismatch: got %r", typ)
        raise InvalidAttestationError(description="invalid_attestation_typ")

    # 3. Extract kid from header (OPTIONAL per spec), iss from payload
    kid = header.get("kid")
    if kid is not None and not isinstance(kid, str):
        logger.debug("Attestation header kid invalid type: %s", type(kid).__name__)
        raise InvalidAttestationError(description="invalid_kid")
    issuer = _required_claim_str(claims, "iss")
    logger.debug("Attestation iss=%s kid=%s", issuer, kid)

    # 4. Look up provider key(s) by iss + optional kid (§9 step 5)
    provider_key = await _lookup_provider_key(issuer, kid or None)
    if not provider_key:
        logger.debug("Attestation provider untrusted/unknown: iss=%s kid=%s", issuer, kid)
        raise InvalidAttestationError(description="untrusted_provider")

    # 5. Verify signature using provider's public key (§9 step 5)
    verified_claims = _verify_signature(client_attestation, provider_key)

    # 6. Validate required claims (§5.1)
    subject = _required_claim_str(verified_claims, "sub")
    issued_at = verified_claims.get("iat")
    expires_at = verified_claims.get("exp")
    if not isinstance(expires_at, int):
        logger.debug(
            "Attestation missing/invalid exp: type=%s", type(expires_at).__name__
        )
        raise InvalidAttestationError(description="missing_exp")

    # 7. Check time validity (§9 step 11)
    skew = int(settings.ATTESTATION_CLOCK_SKEW_SECONDS)
    now = _now_ts()
    if issued_at is not None and int(issued_at) > now + skew:
        logger.debug(
            "Attestation iat in future: iat=%s now=%d skew=%d iss=%s",
            issued_at,
            now,
            skew,
            issuer,
        )
        raise InvalidAttestationError(description="attestation_not_yet_valid")
    if int(expires_at) <= now - skew:
        logger.debug(
            "Attestation expired: exp=%d now=%d skew=%d iss=%s sub=%s",
            int(expires_at),
            now,
            skew,
            issuer,
            subject,
        )
        raise InvalidAttestationError(description="attestation_expired")
    nbf = verified_claims.get("nbf")
    if isinstance(nbf, int) and nbf > now + skew:
        logger.debug(
            "Attestation nbf in future: nbf=%d now=%d skew=%d iss=%s",
            nbf,
            now,
            skew,
            issuer,
        )
        raise InvalidAttestationError(description="attestation_not_yet_valid")

    # 8. Extract cnf.jwk — REQUIRED per §5.1
    cnf_jwk = _extract_cnf_jwk(verified_claims)
    if not cnf_jwk:
        logger.debug(
            "Attestation missing cnf.jwk: cnf=%r iss=%s sub=%s",
            verified_claims.get("cnf"),
            issuer,
            subject,
        )
        raise InvalidAttestationError(description="missing_cnf_jwk")

    # 8b. cnf key MUST NOT be a private key (§9 step 6)
    if "d" in cnf_jwk:
        logger.debug(
            "Attestation cnf.jwk contains private key material: iss=%s sub=%s kty=%s",
            issuer,
            subject,
            cnf_jwk.get("kty"),
        )
        raise InvalidAttestationError(description="cnf_contains_private_key")

    cnf_jkt = _thumbprint(cnf_jwk)
    logger.debug("Attestation cnf jkt=%s (kty=%s)", cnf_jkt, cnf_jwk.get("kty"))

    # --- Attestation PoP JWT validation (§5.2, §9 steps 7-10) ---

    if not client_attestation_pop:
        logger.debug("Attestation PoP missing: iss=%s sub=%s", issuer, subject)
        raise InvalidAttestationError(description="missing_client_attestation_pop")

    # 9. Validate PoP typ header
    # (§5.2: REQUIRED, MUST be "oauth-client-attestation-pop+jwt")
    pop_header, _ = _jwt_extract(client_attestation_pop)
    pop_typ = pop_header.get("typ")
    if pop_typ != "oauth-client-attestation-pop+jwt":
        logger.debug("Attestation PoP typ mismatch: got %r", pop_typ)
        raise InvalidAttestationError(description="invalid_attestation_pop_typ")

    # 10. Verify PoP signature using cnf.jwk from attestation (§9 step 7)
    pop_claims = _verify_signature(
        client_attestation_pop, cnf_jwk, error="attestation_pop_signature_invalid"
    )
    logger.debug(
        "Attestation PoP claims keys=%s aud=%r iat=%s exp=%s",
        sorted(pop_claims.keys()),
        pop_claims.get("aud"),
        pop_claims.get("iat"),
        pop_claims.get("exp"),
    )

    # 11. Verify PoP aud (§5.2: REQUIRED, must be AS issuer identifier)
    pop_aud = pop_claims.get("aud")
    if not pop_aud:
        logger.debug("Attestation PoP missing aud: iss=%s sub=%s", issuer, subject)
        raise InvalidAttestationError(description="missing_attestation_pop_aud")

    # 11b. Validate PoP aud value matches the expected AS issuer (§5.2, §8 step 10)
    aud_values = pop_aud if isinstance(pop_aud, list) else [pop_aud]
    if expected_audience not in aud_values:
        logger.debug(
            "Attestation PoP aud mismatch: expected=%s got=%r iss=%s sub=%s",
            expected_audience,
            pop_aud,
            issuer,
            subject,
        )
        raise InvalidAttestationError(description="attestation_pop_aud_mismatch")

    # 12. Verify PoP jti is present (§5.2: REQUIRED)
    pop_jti = pop_claims.get("jti")
    if not isinstance(pop_jti, str) or not pop_jti:
        logger.debug(
            "Attestation PoP missing/invalid jti: type=%s iss=%s sub=%s",
            type(pop_jti).__name__,
            issuer,
            subject,
        )
        raise InvalidAttestationError(description="missing_attestation_pop_jti")

    # 12b. Check jti replay (§12.1: SHOULD detect replay via jti)
    jti_window = _jti_window()
    if not await _attest_pop_jti_cache.check_and_store(
        pop_jti, db, expires_at=now + jti_window
    ):
        logger.debug(
            "Attestation PoP jti replay detected: jti=%s iss=%s sub=%s",
            pop_jti,
            issuer,
            subject,
        )
        raise InvalidAttestationError(description="attestation_pop_jti_replay")

    # 13. Verify PoP iat is present and within window (§5.2: REQUIRED)
    pop_iat = pop_claims.get("iat")
    if not isinstance(pop_iat, int):
        logger.debug(
            "Attestation PoP missing/invalid iat: type=%s iss=%s sub=%s",
            type(pop_iat).__name__,
            issuer,
            subject,
        )
        raise InvalidAttestationError(description="missing_attestation_pop_iat")
    if pop_iat > now + skew:
        logger.debug(
            "Attestation PoP iat in future: iat=%d now=%d skew=%d iss=%s",
            pop_iat,
            now,
            skew,
            issuer,
        )
        raise InvalidAttestationError(description="attestation_pop_not_yet_valid")
    if pop_iat < now - jti_window:
        logger.debug(
            "Attestation PoP too old: iat=%d now=%d window=%d iss=%s",
            pop_iat,
            now,
            jti_window,
            issuer,
        )
        raise InvalidAttestationError(description="attestation_pop_too_old")

    # 14. Verify PoP nbf if present (RFC7519 via §5.2 rule 5)
    pop_nbf = pop_claims.get("nbf")
    if isinstance(pop_nbf, int) and pop_nbf > now + skew:
        logger.debug(
            "Attestation PoP nbf in future: nbf=%d now=%d skew=%d iss=%s",
            pop_nbf,
            now,
            skew,
            issuer,
        )
        raise InvalidAttestationError(description="attestation_pop_not_yet_valid")

    # 15. Verify PoP exp if present (RFC7519 via §5.2 rule 5)
    pop_exp = pop_claims.get("exp")
    if isinstance(pop_exp, int) and pop_exp <= now - skew:
        logger.debug(
            "Attestation PoP exp passed: exp=%d now=%d skew=%d iss=%s",
            pop_exp,
            now,
            skew,
            issuer,
        )
        raise InvalidAttestationError(description="attestation_pop_expired")

    logger.debug(
        "Attestation verified: iss=%s sub=%s kid=%s cnf_jkt=%s pop_jti=%s",
        issuer,
        subject,
        kid,
        cnf_jkt,
        pop_jti,
    )

    return {
        "present": True,
        "verified": True,
        "iss": issuer,
        "kid": kid,
        "sub": subject,
        "cnf_jkt": cnf_jkt,
        "pop_jti": pop_jti,
        "iat": issued_at,
        "exp": expires_at,
    }
