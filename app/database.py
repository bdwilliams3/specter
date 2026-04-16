import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
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


_NEW_THREAT_COLUMNS = [
    ("threat_name",       "VARCHAR DEFAULT ''"),
    ("principal_role",    "VARCHAR"),
    ("principal_subject", "VARCHAR"),
    ("method",            "VARCHAR"),
    ("resource",          "VARCHAR"),
    ("namespace",         "VARCHAR"),
    ("source_ips",        "JSON"),
]


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for col, typedef in _NEW_THREAT_COLUMNS:
            try:
                await conn.execute(text(f"ALTER TABLE threat_events ADD COLUMN {col} {typedef}"))
            except Exception:
                pass  # column already exists
