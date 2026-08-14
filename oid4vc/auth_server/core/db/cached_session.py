"""LRU-cached async engine pool, keyed by (url, schema)."""

import asyncio
from collections import OrderedDict
from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

_engines: OrderedDict[tuple[str, str], AsyncEngine] = OrderedDict()
_DEFAULT_MAX = 64


def _session_factory(
    async_url: str, schema: str, *, max_engines: int = _DEFAULT_MAX
) -> async_sessionmaker[AsyncSession]:
    """Get or create a sessionmaker, evicting LRU engines over max."""
    key = (async_url, schema)
    if key in _engines:
        _engines.move_to_end(key)
    else:
        _engines[key] = create_async_engine(
            async_url,
            pool_pre_ping=True,
            connect_args={"server_settings": {"search_path": schema}},
        )
        while len(_engines) > max_engines:
            _, evicted = _engines.popitem(last=False)
            try:
                asyncio.get_event_loop().create_task(evicted.dispose())
            except RuntimeError:
                pass
    return async_sessionmaker(_engines[key], expire_on_commit=False)


@asynccontextmanager
async def cached_session(async_url: str, schema: str) -> AsyncIterator[AsyncSession]:
    """Context manager for a session from the cached pool."""
    session = _session_factory(async_url, schema)()
    try:
        yield session
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def dispose_cached_engines() -> None:
    """Shut down all pooled engines."""
    for engine in _engines.values():
        await engine.dispose()
    _engines.clear()
