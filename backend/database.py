import os
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./vuln_scanner.db"  # local dev fallback
)

# Neon / Render sometimes pass postgres:// — normalize it
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Map to correct async driver
# Normalize all PostgreSQL URLs to psycopg async, which handles Neon sslmode cleanly.
if DATABASE_URL.startswith(("postgresql://", "postgresql+psycopg://", "postgresql+asyncpg://")):
    connect_url = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
    if connect_url.startswith("postgresql+asyncpg://"):
        connect_url = connect_url.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)

    # Extract sslmode from URL params if present
    import urllib.parse as _urlparse
    _parsed = _urlparse.urlparse(DATABASE_URL)
    _qs = _urlparse.parse_qs(_parsed.query)
    _sslmode = _qs.get("sslmode", [""])[0]

    # Rebuild URL without ssl params (psycopg handles via connect_args)
    _clean_qs = {k: v for k, v in _qs.items() if k not in ("sslmode", "channel_binding")}
    _clean_parsed = _parsed._replace(
        query=_urlparse.urlencode({k: v[0] for k, v in _clean_qs.items()})
    )
    connect_url = _urlparse.urlunparse(_clean_parsed).replace("postgresql://", "postgresql+psycopg://", 1)
    if connect_url.startswith("postgresql+asyncpg://"):
        connect_url = connect_url.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)

    _connect_args: dict = {}
    if _sslmode == "require":
        _connect_args = {"sslmode": "require"}

    engine = create_async_engine(
        connect_url,
        echo=False,
        pool_pre_ping=True,
        connect_args=_connect_args,
    )
elif DATABASE_URL.startswith("sqlite"):
    engine = create_async_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})
else:
    engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    """Create all tables on startup (no Alembic — free-tier friendly)."""
    from backend.models import ScanJob, Finding  # noqa: F401
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
