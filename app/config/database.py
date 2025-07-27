"""Database configuration and session management."""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.config.settings import settings


# Create async engine
if settings.is_testing:
    # For testing, use NullPool without pool parameters
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DATABASE_ECHO,
        pool_pre_ping=True,
        pool_recycle=3600,
        poolclass=NullPool,
    )
else:
    # For development/production, use connection pooling
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DATABASE_ECHO,
        pool_size=settings.DATABASE_POOL_SIZE,
        max_overflow=settings.DATABASE_MAX_OVERFLOW,
        pool_pre_ping=True,
        pool_recycle=3600,
    )

# Create async session factory
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency function to get database session for FastAPI dependency injection.
    
    Yields:
        AsyncSession: Database session
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_session() -> AsyncSession:
    """
    Get a database session directly (not for dependency injection).
    
    Returns:
        AsyncSession: Database session that must be closed manually
    """
    return AsyncSessionLocal()


class DatabaseManager:
    """Database manager for handling sessions and connections."""
    
    @staticmethod
    async def get_session() -> AsyncSession:
        """Get a new database session."""
        return AsyncSessionLocal()
    
    @staticmethod
    async def close_session(session: AsyncSession) -> None:
        """Close a database session."""
        try:
            await session.close()
        except Exception:
            pass
    
    @staticmethod
    async def rollback_session(session: AsyncSession) -> None:
        """Rollback a database session."""
        try:
            await session.rollback()
        except Exception:
            pass


async def create_tables():
    """Create all database tables."""
    from app.models.base import Base
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_tables():
    """Drop all database tables."""
    from app.models.base import Base
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def init_db():
    """Initialize database connection and create tables if needed."""
    # Import all models to ensure they are registered with SQLAlchemy
    from app.models import (
        User, Role, Scope, ServiceClient, RefreshToken,
        user_roles, role_scopes, service_client_scopes
    )
    
    # Create tables in development/testing environments
    if settings.ENVIRONMENT in ["development", "testing"]:
        await create_tables()


async def close_db():
    """Close database connections."""
    await engine.dispose()