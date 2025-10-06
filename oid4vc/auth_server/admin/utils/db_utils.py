"""Utilities for working with databases."""

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from sqlalchemy.engine import URL

from admin.config import settings
from admin.models import Tenant
from admin.utils.crypto import decrypt_db_password


def build_async_url(db: str, user: str, password: str) -> str:
    """Build async DB connection string."""
    url = URL.create(
        drivername=settings.DB_DRIVER_ASYNC,
        username=user,
        password=password,
        host=settings.DB_HOST,
        port=settings.DB_PORT,
        database=db,
    )
    return url.render_as_string(hide_password=False)


def build_sync_url(db: str, user: str, password: str) -> str:
    """Build sync DB connection string."""
    url = URL.create(
        drivername=settings.DB_DRIVER_SYNC,
        username=user,
        password=password,
        host=settings.DB_HOST,
        port=settings.DB_PORT,
        database=db,
    )
    return url.render_as_string(hide_password=False)


def resolve_tenant_urls(tenant: Tenant) -> tuple[str, str, str]:
    """Build DB connection strings for a tenant."""
    db = tenant.db_name
    schema = tenant.db_schema or settings.TENANT_DB_SCHEMA
    user = tenant.db_user
    pwd_enc = tenant.db_pwd_enc
    pwd = decrypt_db_password(pwd_enc)  # call your crypto helper here

    async_url = build_async_url(db, user, pwd)
    sync_url = build_sync_url(db, user, pwd)
    return async_url, sync_url, schema


def url_to_dsn(url: str) -> str:
    """Convert SQLAlchemy URL to psycopg DSN by removing '+driver' suffix."""
    return re.sub(r"\+\w+", "", url, count=1)


def mask_dsn(dsn: str) -> str:
    """Hide password when printing DB URLs."""
    # postgresql+X://user:pass@host -> postgresql+X://user:****@host
    return re.sub(r"//([^:/@]+):([^@]*)@", r"//\1:****@", dsn)


def ensure_search_path(dsn: str, schema: str) -> str:
    """Ensure DSN has ?options=-csearch_path=<schema> (if not already set)."""
    try:
        u = urlparse(dsn)
        q = dict(parse_qsl(u.query, keep_blank_values=True))
        # Respect an existing options param that sets search_path
        if any(k.lower() == "options" and "search_path" in v for k, v in q.items()):
            return dsn
        q["options"] = f"-csearch_path={schema}"
        new_query = urlencode(q, doseq=True)
        return urlunparse((u.scheme, u.netloc, u.path, u.params, new_query, u.fragment))
    except Exception:
        return dsn
