"""Revocation-specific test fixtures.

This module contains fixtures for revocation tests that require
function-scoped isolation to prevent state pollution between tests.
"""

import pytest


# Revocation tests should use function-scoped credential configurations
# to ensure that revoking a credential in one test doesn't affect another
@pytest.fixture(scope="function")
def revocation_isolation():
    """Marker fixture to ensure function-scope isolation for revocation tests."""
    return True


# Future revocation-specific fixtures can be added here
# For example:
# - Status list management helpers
# - Revocation status checkers
# - Multiple credential test data for revocation batches
