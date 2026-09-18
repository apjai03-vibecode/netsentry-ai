"""Database connection, session management, and base declarative class."""
import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from app.config import settings

logger = logging.getLogger(__name__)

# Handle SQLite vs PostgreSQL engine arguments
engine_kwargs = {"echo": False}
if settings.DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_async_engine(settings.DATABASE_URL, **engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy models."""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that yields an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create all database tables on startup and seed default demo accounts."""
    # Import models so Base.metadata is fully populated
    from app import models  # noqa: F401
    from app.models import User
    from app.auth import get_password_hash
    from sqlalchemy import select

    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables initialized successfully.")

        # Seed default demo users if they don't already exist
        async with AsyncSessionLocal() as session:
            demo_accounts = [
                ("analyst", "analyst@netsentry.internal", "Password123!", "analyst"),
                ("admin", "admin@netsentry.internal", "Password123!", "admin"),
            ]
            for uname, email, pwd, role in demo_accounts:
                stmt = select(User).where(User.username == uname)
                res = await session.execute(stmt)
                if not res.scalar_one_or_none():
                    user = User(
                        username=uname,
                        email=email,
                        hashed_password=get_password_hash(pwd),
                        role=role,
                        is_active=True,
                    )
                    session.add(user)
                    logger.info(f"Seeded demo account '{uname}'.")
            await session.commit()

    except Exception as e:
        logger.warning(
            f"Failed to initialize database tables automatically: {e}. "
            "Ensure PostgreSQL is running or configure SQLite for local development."
        )
