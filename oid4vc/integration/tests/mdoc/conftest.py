"""mDOC-specific test fixtures.

This module contains PKI and trust anchor fixtures for mDOC tests.
These fixtures are separated from the main conftest to keep them
organized and only loaded when needed for mDOC tests.
"""

# PKI fixtures are kept in root conftest.py due to session scope
# and shared usage across multiple test directories.
# This file exists for future mDOC-specific fixtures and to
# maintain the hierarchical conftest structure.

# Import commonly needed modules for mDOC tests


# Future mDOC-specific fixtures can be added here
# For example:
# - mDOC format validators
# - ISO namespace helpers
# - Age predicate test data
