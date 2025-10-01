"""Path helpers for project structure."""

from pathlib import Path


def project_root() -> Path:
    """Return the project root (where pyproject.toml lives)."""
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "pyproject.toml").exists():
            return parent
    raise RuntimeError("Could not locate project root (pyproject.toml not found)")


def tenant_alembic_dir() -> Path:
    """Return path to tenant alembic scripts."""
    return project_root() / "alembic" / "tenant"


def admin_alembic_dir() -> Path:
    """Return path to admin alembic scripts."""
    return project_root() / "alembic" / "admin"
