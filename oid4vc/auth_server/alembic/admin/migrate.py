"""Alembic migrations for the admin database."""

import os
import pathlib
import subprocess
import sys

from admin.config import settings
from admin.utils.db_utils import mask_dsn
from core.utils.logging import get_logger

logger = get_logger(__name__)

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
ADMIN_INI = "alembic/admin/alembic.ini"


def run(cmd: list[str], env: dict[str, str] | None = None) -> None:
    """Run a command."""
    logger.info("+ %s", " ".join(cmd))
    rv = subprocess.run(cmd, cwd=PROJECT_ROOT, env=env or os.environ.copy())
    if rv.returncode != 0:
        sys.exit(rv.returncode)


def main() -> None:
    """Run Alembic migrations for the admin DB."""
    env = os.environ.copy()

    # Combine ALEMBIC_ARGS env and CLI args (env first, CLI overrides/appends)
    extra = [a for a in env.get("ALEMBIC_ARGS", "").split() if a]
    cli = sys.argv[1:]
    args = (extra + cli) if (extra or cli) else ["upgrade", "head"]

    url = env.get("ALEMBIC_DB_URL") or settings.DB_URL_SYNC
    schema = env.get("ALEMBIC_DB_SCHEMA") or settings.DB_SCHEMA

    if not url:
        logger.error("ERROR: ALEMBIC_DB_URL not set.")
        sys.exit(2)

    env["ALEMBIC_DB_URL"] = url
    env["ALEMBIC_DB_SCHEMA"] = schema

    logger.info(f"Using ALEMBIC_DB_URL: {mask_dsn(url)}")
    run(["alembic", "-c", ADMIN_INI, *args], env=env)


if __name__ == "__main__":
    main()
