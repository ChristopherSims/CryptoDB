"""Database connection and session management."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from cryptodb.config import settings

_engine = None


def _ensure_engine():
    """Lazy-initialize the async engine."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            f"sqlite+aiosqlite:///{settings.db_path}",
            echo=False,
            future=True,
        )
    return _engine


def get_session_local():
    """Return a session class bound to the current engine."""
    engine = _ensure_engine()
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


def reset_engine() -> None:
    """Dispose the current engine so the next call re-creates it.

    Used primarily by tests that change ``settings.db_path``.
    """
    global _engine
    if _engine is not None:
        _engine.sync_engine.dispose()
        _engine = None


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async DB session."""
    SessionLocal = get_session_local()
    async with SessionLocal() as session:
        yield session


async def init_db() -> None:
    """Create all metadata tables."""
    from cryptodb.db.metadata import Base

    engine = _ensure_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@asynccontextmanager
async def session_context() -> AsyncGenerator[AsyncSession, None]:
    """Async context manager for DB sessions."""
    SessionLocal = get_session_local()
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
