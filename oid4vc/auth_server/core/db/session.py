"""Database session manager."""

import contextlib
from typing import AsyncIterator, Callable

from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


class DatabaseSessionManager:
    """Async SQLAlchemy session manager."""

    def __init__(self, *, search_path: str | None = None) -> None:
        """Constructor."""
        self._engine: AsyncEngine | None = None
        self._sessionmaker: async_sessionmaker[AsyncSession] | None = None
        self._search_path = search_path

    def init(self, url: str) -> None:
        """Initialize engine and sessionmaker."""
        connect_args = {}
        if self._search_path:
            connect_args["server_settings"] = {"search_path": self._search_path}

        self._engine = create_async_engine(
            url,
            pool_pre_ping=True,
            connect_args=connect_args or None,
            future=True,
        )
        self._sessionmaker = async_sessionmaker(
            self._engine, expire_on_commit=False, autoflush=False
        )

    async def close(self) -> None:
        """Dispose engine and drop references."""
        # BUGFIX: previous version checked `if self._engine is None`.
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._sessionmaker = None

    @contextlib.asynccontextmanager
    async def connect(self) -> AsyncIterator[AsyncConnection]:
        """Yield an AsyncConnection within a BEGIN block."""
        if self._engine is None:
            raise RuntimeError("DatabaseSessionManager is not initialized")
        async with self._engine.begin() as conn:
            yield conn

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield an AsyncSession; caller manages commit/rollback."""
        if self._sessionmaker is None:
            raise RuntimeError("DatabaseSessionManager is not initialized")
        session = self._sessionmaker()
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    async def create_all(self, connection: AsyncConnection, base) -> None:
        """Create all tables for the given DeclarativeBase."""
        await connection.run_sync(base.metadata.create_all)

    async def drop_all(self, connection: AsyncConnection, base) -> None:
        """Drop all tables for the given DeclarativeBase."""
        await connection.run_sync(base.metadata.drop_all)


def make_session_dependency(
    manager: DatabaseSessionManager,
) -> Callable[[], AsyncIterator[AsyncSession]]:
    """FastAPI dependency that yields an AsyncSession."""

    async def _dep() -> AsyncIterator[AsyncSession]:
        async with manager.session() as session:
            yield session

    return _dep
