from collections.abc import AsyncGenerator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import settings

engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


@event.listens_for(engine.sync_engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record) -> None:
    """SQLite connect-time setup.

    foreign_keys: SQLAlchemy's ondelete=CASCADE needs the pragma (SQLite
    ships with FK enforcement off). WAL: readers never block the writer,
    so page renders cannot trip over a concurrent purchase write.
    Guarded by dialect so a postgres URL still works unchanged.
    """
    if engine.url.get_dialect().name != "sqlite":
        return
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        yield session


async def init_db() -> None:
    from . import models  # noqa: F401  (register models on the metadata)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
