"""Alembic migrations for the admin database."""

from logging.config import fileConfig

from alembic import context
from core.db.alembic import run_offline, run_online
from core.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


if context.is_offline_mode():
    run_offline(Base.metadata, default_schema="public")
else:
    run_online(Base.metadata, default_schema="public")
