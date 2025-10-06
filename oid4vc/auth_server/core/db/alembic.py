"""Alembic helpers."""

import os

from sqlalchemy import MetaData, engine_from_config, pool, text

from alembic import context


def _resolve_url_and_schema(default_schema: str) -> tuple[str, str]:
    cfg = context.config
    ini = cfg.get_section(cfg.config_ini_section) or {}
    url = os.getenv("ALEMBIC_DB_URL") or ini.get("sqlalchemy.url")
    if not url:
        raise RuntimeError("No database URL for Alembic.")
    schema = (
        os.getenv("ALEMBIC_DB_SCHEMA")
        or cfg.get_main_option("version_table_schema")
        or default_schema
    )
    return url, schema


def run_offline(metadata: MetaData | None, default_schema: str) -> None:
    """Run migrations in 'offline' mode."""
    url, schema = _resolve_url_and_schema(default_schema)
    context.configure(
        url=url,
        target_metadata=metadata,
        include_schemas=True,
        version_table_schema=schema,
        literal_binds=True,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_online(metadata: MetaData | None, default_schema: str) -> None:
    """Run migrations in 'online' mode."""
    cfg = context.config.get_section(context.config.config_ini_section) or {}
    url, schema = _resolve_url_and_schema(default_schema)
    cfg["sqlalchemy.url"] = url

    eng = engine_from_config(
        cfg, prefix="sqlalchemy.", poolclass=pool.NullPool, future=True
    )
    with eng.connect() as conn:
        if schema != "public":
            conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
            conn.execute(text(f'SET search_path TO "{schema}"'))
            conn.commit()

        context.configure(
            connection=conn,
            target_metadata=metadata,
            include_schemas=True,
            version_table_schema=schema,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()
