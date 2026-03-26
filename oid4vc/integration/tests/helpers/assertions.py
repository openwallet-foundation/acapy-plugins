"""Assertion helpers for OID4VC integration tests."""

import base64
import json
from typing import Any


def assert_disclosed_claims(
    matched_credentials: dict[str, Any],
    query_id: str,
    expected_claims: list[str],
    *,
    check_nested: bool = True,
) -> None:
    """Assert that expected claims are present in matched credentials.

    Args:
        matched_credentials: The matched_credentials dict from presentation result
        query_id: The credential query ID (e.g., "employee_verification")
        expected_claims: List of claim names that MUST be present
        check_nested: If True, search recursively in nested dicts

    Raises:
        AssertionError: If query_id not found or any expected claim is missing
    """
    assert matched_credentials is not None, "matched_credentials is None"
    assert query_id in matched_credentials, (
        f"Query ID '{query_id}' not found in matched_credentials. "
        f"Available keys: {list(matched_credentials.keys())}"
    )

    disclosed_payload = matched_credentials[query_id]

    def find_claim(data: Any, claim_name: str) -> bool:
        """Recursively search for a claim in nested structure."""
        if isinstance(data, dict):
            if claim_name in data:
                return True
            if check_nested:
                return any(find_claim(v, claim_name) for v in data.values())
        return False

    missing_claims = [
        claim for claim in expected_claims if not find_claim(disclosed_payload, claim)
    ]

    assert not missing_claims, (
        f"Expected claims not found in presentation: {missing_claims}. "
        f"Disclosed payload keys: {_get_all_keys(disclosed_payload)}"
    )


def assert_hidden_claims(
    matched_credentials: dict[str, Any],
    query_id: str,
    excluded_claims: list[str],
    *,
    check_nested: bool = True,
) -> None:
    """Assert that sensitive claims are NOT disclosed in the presentation.

    Args:
        matched_credentials: The matched_credentials dict from presentation result
        query_id: The credential query ID (e.g., "employee_verification")
        excluded_claims: List of claim names that MUST NOT be present
        check_nested: If True, search recursively in nested dicts

    Raises:
        AssertionError: If query_id not found or any excluded claim is present
    """
    assert matched_credentials is not None, "matched_credentials is None"
    assert query_id in matched_credentials, (
        f"Query ID '{query_id}' not found in matched_credentials. "
        f"Available keys: {list(matched_credentials.keys())}"
    )

    disclosed_payload = matched_credentials[query_id]

    def find_claim(data: Any, claim_name: str) -> bool:
        """Recursively search for a claim in nested structure."""
        if isinstance(data, dict):
            if claim_name in data:
                return True
            if check_nested:
                return any(find_claim(v, claim_name) for v in data.values())
        return False

    leaked_claims = [
        claim for claim in excluded_claims if find_claim(disclosed_payload, claim)
    ]

    assert not leaked_claims, (
        f"Sensitive claims were disclosed but should NOT be: {leaked_claims}. "
        f"These claims should have been excluded via selective disclosure."
    )


def assert_selective_disclosure(
    matched_credentials: dict[str, Any],
    query_id: str,
    *,
    must_have: list[str] | None = None,
    must_not_have: list[str] | None = None,
    check_nested: bool = True,
) -> None:
    """Convenience function to verify both present and absent claims.

    Args:
        matched_credentials: The matched_credentials dict from presentation result
        query_id: The credential query ID
        must_have: Claims that MUST be disclosed
        must_not_have: Claims that MUST NOT be disclosed
        check_nested: If True, search recursively in nested dicts
    """
    if must_have:
        assert_disclosed_claims(
            matched_credentials, query_id, must_have, check_nested=check_nested
        )
    if must_not_have:
        assert_hidden_claims(
            matched_credentials, query_id, must_not_have, check_nested=check_nested
        )


def assert_valid_sd_jwt(
    credential: str, expected_claims: list[str] | None = None
) -> dict:
    """Assert that credential is a valid SD-JWT and optionally check claims.

    Args:
        credential: The SD-JWT credential string
        expected_claims: Optional list of claim names that should be present

    Returns:
        The decoded payload from the JWT

    Raises:
        AssertionError: If credential is invalid or missing expected claims
    """
    assert credential, "Credential is empty"
    assert isinstance(credential, str), f"Expected string, got {type(credential)}"

    # SD-JWT format: <issuer-jwt>~<disclosure>~<disclosure>...~<kb-jwt>
    parts = credential.split("~")
    assert len(parts) >= 2, (
        f"Invalid SD-JWT format: expected at least 2 parts, got {len(parts)}"
    )

    # Decode the issuer JWT (first part)
    issuer_jwt = parts[0]
    jwt_parts = issuer_jwt.split(".")
    assert len(jwt_parts) == 3, (
        f"Invalid JWT format: expected 3 parts, got {len(jwt_parts)}"
    )

    # Decode payload (add padding if needed)
    payload_b64 = jwt_parts[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding

    payload_bytes = base64.urlsafe_b64decode(payload_b64)
    payload = json.loads(payload_bytes)

    # Basic SD-JWT checks
    assert "iss" in payload, "Missing 'iss' claim in SD-JWT"
    assert "_sd" in payload or "_sd_alg" in payload, (
        "Missing SD-JWT selective disclosure claims"
    )

    if expected_claims:
        # Note: With selective disclosure, claims may be in disclosures, not payload
        # This is a basic check - full verification needs disclosure parsing
        disclosed = set(payload.keys())
        missing = [
            c
            for c in expected_claims
            if c not in disclosed and c not in ["_sd", "_sd_alg"]
        ]
        # Allow missing if they're selectively disclosed
        if missing and "_sd" not in payload:
            assert False, (
                f"Expected claims not in payload and no selective disclosures: {missing}"
            )

    return payload


def assert_mdoc_structure(mdoc_data: bytes | dict, doctype: str) -> None:
    """Assert that data has valid mDOC structure.

    Args:
        mdoc_data: The mDOC data (bytes or decoded dict)
        doctype: Expected doctype (e.g., "org.iso.18013.5.1.mDL")

    Raises:
        AssertionError: If mDOC structure is invalid
    """
    if isinstance(mdoc_data, bytes):
        # If bytes, it should be CBOR-encoded
        try:
            import cbor2

            mdoc_data = cbor2.loads(mdoc_data)
        except Exception as e:
            assert False, f"Failed to decode mDOC CBOR: {e}"

    assert isinstance(mdoc_data, dict), f"Expected dict, got {type(mdoc_data)}"
    assert "docType" in mdoc_data or "doctype" in mdoc_data, "Missing docType in mDOC"

    actual_doctype = mdoc_data.get("docType") or mdoc_data.get("doctype")
    assert actual_doctype == doctype, (
        f"Expected doctype {doctype}, got {actual_doctype}"
    )

    # Check for namespaced data
    assert "nameSpaces" in mdoc_data or "namespaces" in mdoc_data, (
        "Missing nameSpaces in mDOC"
    )


def assert_presentation_successful(presentation_result: dict) -> None:
    """Assert that presentation was successful.

    Args:
        presentation_result: The presentation result from the OID4VP verifier.
            This is an OID4VPPresentation record with 'verified' (bool) and
            'state' ('presentation-valid' | 'presentation-invalid') fields.

    Raises:
        AssertionError: If presentation failed
    """
    assert presentation_result is not None, "Presentation result is None"
    # OID4VP records use 'verified' (bool) and 'state' rather than 'success'
    verified = presentation_result.get("verified")
    state = presentation_result.get("state")
    assert verified is True or state == "presentation-valid", (
        f"Presentation failed: state={state!r}, verified={verified!r}, "
        f"errors={presentation_result.get('errors', 'Unknown error')}"
    )


def assert_credential_revoked(credential_status: dict, exchange_id: str) -> None:
    """Assert that credential has been revoked.

    Args:
        credential_status: Status response from verifier
        exchange_id: Exchange ID of the revoked credential

    Raises:
        AssertionError: If credential is not revoked
    """
    assert credential_status is not None, "Credential status is None"
    assert "status" in credential_status, "Missing 'status' field"

    status_value = credential_status["status"]
    # Status "1" typically indicates revoked in status list
    assert status_value in ["1", 1, "revoked"], (
        f"Expected credential {exchange_id} to be revoked, got status: {status_value}"
    )


def _get_all_keys(data: Any, prefix: str = "") -> set[str]:
    """Get all keys from a nested dict structure for error reporting."""
    keys: set[str] = set()
    if isinstance(data, dict):
        for k, v in data.items():
            full_key = f"{prefix}.{k}" if prefix else k
            keys.add(full_key)
            keys.update(_get_all_keys(v, full_key))
    return keys


# Alias for backward compatibility with test_utils.py
assert_claims_present = assert_disclosed_claims
assert_claims_absent = assert_hidden_claims
