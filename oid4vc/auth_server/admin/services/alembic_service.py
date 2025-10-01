"""Alembic helpers used by provisioning flow and admin routes."""

from alembic import command
from alembic.config import Config
from core.utils.paths import tenant_alembic_dir


def run_tenant_migration(
    *, sync_url: str, schema: str, action: str, rev: str | None = None
) -> None:
    """Run a tenant migration via Alembic API.

    Args:
        sync_url: SQLAlchemy sync URL (e.g., postgresql+psycopg://...).
        schema: Target schema for version table and search_path.
        action: "upgrade" or "downgrade".
        rev: Revision target (defaults: head for upgrade, -1 for downgrade).
    """
    cfg = Config()
    cfg.set_main_option("script_location", str(tenant_alembic_dir()))
    cfg.set_main_option("sqlalchemy.url", sync_url)
    cfg.set_main_option("version_table_schema", schema)

    target = rev or ("head" if action == "upgrade" else "-1")

    if action == "upgrade":
        command.upgrade(cfg, target)
    elif action == "downgrade":
        command.downgrade(cfg, target)
    else:
        raise ValueError("invalid action; expected 'upgrade' or 'downgrade'")
