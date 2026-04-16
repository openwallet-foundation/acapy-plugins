"""Compatibility shim — superseded by migrate.py.

Import from ``oid4vc.migrate`` instead.
"""

# Re-export so any code that still imports from here keeps working.
from .migrate import run_migrations as run_upgrades  # noqa: F401
