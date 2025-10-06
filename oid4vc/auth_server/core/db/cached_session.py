"""Cached session factory."""

from contextlib import asynccontextmanager
from functools import lru_cache
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@lru_cache(maxsize=256)
def _session_factory(async_url: str, schema: str) -> async_sessionmaker[AsyncSession]:
    """Return a cached sessionmaker for the given database and schema."""
    engine = create_async_engine(
        async_url,
        pool_pre_ping=True,
        connect_args={"server_settings": {"search_path": schema}},
    )
    return async_sessionmaker(engine, expire_on_commit=False)


@asynccontextmanager
async def cached_session(async_url: str, schema: str) -> AsyncIterator[AsyncSession]:
    """Yield an AsyncSession backed by a cached factory."""
    session = _session_factory(async_url, schema)()
    try:
        yield session
    finally:
        await session.close()


async def dispose_cached_engines() -> None:
    """Dispose all cached engines."""
    factories = list(_session_factory.cache_info().cache.keys())  # type: ignore[attr-defined]
    for args in factories:
        sessionmaker = _session_factory(*args)
        await sessionmaker.bind.dispose()  # type: ignore[union-attr]
    _session_factory.cache_clear()
