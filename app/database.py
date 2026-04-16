import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.config import settings


class Base(DeclarativeBase):
    pass


def get_engine():
    url = settings.database_url
    if url.startswith("sqlite"):
        db_path = settings.sqlite_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        return create_async_engine(url, connect_args={"check_same_thread": False}, echo=False)
    return create_async_engine(url, echo=False)


engine = get_engine()

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
