# tenebrinet/core/database.py
"""
Database management for TenebriNET.

Provides async database connection management using SQLAlchemy with PostgreSQL.
"""
import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base


# Base class for SQLAlchemy models
Base = declarative_base()

# Database URL from environment variable
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://user:password@localhost/tenebrinet_db",
)

# Create the async engine
engine = create_async_engine(DATABASE_URL, echo=False)

# Create a sessionmaker for async sessions
AsyncSessionLocal = async_sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """
    Initialize the database by creating all tables.

    This should be called during application startup to ensure
    all model tables exist in the database.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide an async database session.

    This is typically used as a FastAPI dependency to inject
    database sessions into route handlers.

    Yields:
        AsyncSession: An asynchronous database session.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
