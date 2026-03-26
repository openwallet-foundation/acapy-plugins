"""Utility functions for OID4VC tests.

This module contains helper functions that don't fit into other categories:
- Assertion utilities for claim verification
- Polling/waiting utilities for async operations
- Test helper classes

Most test-specific logic should be in test methods or fixtures.
Use these utilities sparingly - prefer inline test logic when possible.
"""

import asyncio
import logging
from typing import Any

import httpx

LOGGER = logging.getLogger(__name__)


# =============================================================================
# Assertion Utilities
# =============================================================================


def assert_selective_disclosure(
    matched_credentials: dict[str, Any],
    query_id: str,
    *,
    must_have: list[str] | None = None,
    must_not_have: list[str] | None = None,
    check_nested: bool = True,
) -> None:
    """Verify both present and absent claims for selective disclosure.

    Args:
        matched_credentials: The matched_credentials dict from presentation result
        query_id: The credential query ID
        must_have: Claims that MUST be disclosed
        must_not_have: Claims that MUST NOT be disclosed
        check_nested: If True, search recursively in nested dicts
    """
    if must_have:
        assert_claims_present(
            matched_credentials, query_id, must_have, check_nested=check_nested
        )
    if must_not_have:
        assert_claims_absent(
            matched_credentials, query_id, must_not_have, check_nested=check_nested
        )


def assert_claims_present(
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
        """Search for a claim in the data structure."""
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
        f"Expected claims missing from disclosure: {missing_claims}. "
        f"Available keys: {_get_all_keys(disclosed_payload)}"
    )


def assert_claims_absent(
    matched_credentials: dict[str, Any],
    query_id: str,
    excluded_claims: list[str],
    *,
    check_nested: bool = True,
) -> None:
    """Assert that sensitive claims are NOT present in matched credentials.

    Args:
        matched_credentials: The matched_credentials dict from presentation result
        query_id: The credential query ID
        excluded_claims: List of claim names that MUST NOT be present
        check_nested: If True, search recursively in nested dicts

    Raises:
        AssertionError: If any excluded claim is found
    """
    assert matched_credentials is not None, "matched_credentials is None"
    assert query_id in matched_credentials, (
        f"Query ID '{query_id}' not found in matched_credentials"
    )

    disclosed_payload = matched_credentials[query_id]

    def find_claim(data: Any, claim_name: str) -> bool:
        """Search for a claim in the data structure."""
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


def _get_all_keys(data: Any, prefix: str = "") -> set[str]:
    """Get all keys from a nested dict structure for error reporting."""
    keys: set[str] = set()
    if isinstance(data, dict):
        for k, v in data.items():
            full_key = f"{prefix}.{k}" if prefix else k
            keys.add(full_key)
            keys.update(_get_all_keys(v, full_key))
    return keys


# =============================================================================
# Polling/Waiting Utilities
# =============================================================================


async def wait_for_presentation_state(
    client: httpx.AsyncClient,
    presentation_id: str,
    expected_state: str,
    max_retries: int = 15,
    delay: float = 1.0,
) -> dict[str, Any]:
    """Poll presentation endpoint until expected state is reached.

    Args:
        client: HTTP client for verifier admin API
        presentation_id: The presentation ID to poll
        expected_state: Expected state (e.g., "presentation-valid")
        max_retries: Maximum number of polling attempts
        delay: Delay between attempts in seconds

    Returns:
        The presentation record once expected state is reached

    Raises:
        AssertionError: If expected state not reached within max_retries
    """
    for attempt in range(max_retries):
        result = await client.get(f"/oid4vp/presentation/{presentation_id}")
        # Support both Controller (returns dict directly) and httpx.AsyncClient
        # (returns an httpx.Response that needs .json() and .raise_for_status())
        if isinstance(result, dict):
            record = result
        else:
            result.raise_for_status()
            record = result.json()

        current_state = record.get("state")
        if current_state == expected_state:
            return record

        # Check for terminal failure states
        if current_state in ["presentation-invalid", "abandoned", "deleted"]:
            raise AssertionError(
                f"Presentation reached terminal state '{current_state}' "
                f"instead of expected '{expected_state}'. "
                f"Errors: {record.get('errors', 'none')}"
            )

        if attempt < max_retries - 1:
            await asyncio.sleep(delay)

    raise AssertionError(
        f"Presentation did not reach state '{expected_state}' "
        f"after {max_retries} attempts (current: '{current_state}')"
    )
