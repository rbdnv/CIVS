from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.config import get_settings
from app.db.tables import Base

settings = get_settings()

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """
    Dev/demo helper that mirrors the ORM metadata into the database.

    The production/default schema path is Alembic migrations via
    `alembic upgrade head`. Keep this helper only for disposable local
    environments where `AUTO_INIT_DB=true` is explicitly enabled.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
