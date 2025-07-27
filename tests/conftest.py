"""Pytest configuration using real Docker containers for database and Redis setup."""

import asyncio
import pytest
import pytest_asyncio
from typing import AsyncGenerator, Generator
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
import os

from app.main import app
from app.config.database import get_db
from app.config.redis import get_redis, RedisClient
from app.config.settings import Settings
from app.models.base import Base
from app.models.user import User
from app.models.role import Role
from app.models.scope import Scope
from app.models.service_client import ServiceClient
from app.models.refresh_token import RefreshToken
from app.core.password import hash_password
from app.core.jwt import jwt_service


# Test settings fixture using real Docker containers
@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Create test settings using real Docker containers."""
    # Use environment variables with container-aware defaults
    database_url = os.getenv(
        "TEST_DATABASE_URL",
        "postgresql+asyncpg://keystone_test:keystone_test_password@postgres-test:5432/keystone_test"
    )
    redis_url = os.getenv(
        "TEST_REDIS_URL",
        "redis://redis-test:6379/0"
    )
    
    return Settings(
        ENVIRONMENT="testing",
        DEBUG=True,
        DATABASE_URL=database_url,
        REDIS_URL=redis_url,
        JWT_SECRET_KEY="test-secret-key-for-testing-32chars",
        ACCESS_TOKEN_EXPIRE_MINUTES=15,
        REFRESH_TOKEN_EXPIRE_DAYS=30,
        DATABASE_ECHO=False,
        REDIS_DECODE_RESPONSES=True,
    )


# Event loop fixture for async tests
@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# Database engine fixture using real Docker containers
@pytest.fixture(scope="session")
async def test_engine(test_settings: Settings):
    """Create test database engine using real Docker containers."""
    engine = create_async_engine(
        test_settings.DATABASE_URL,
        echo=test_settings.DATABASE_ECHO,
        pool_pre_ping=True,
        pool_recycle=300,
    )
    
    # Wait for database to be ready and create all tables
    max_retries = 60
    for attempt in range(max_retries):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            break
        except Exception as e:
            if attempt == max_retries - 1:
                raise e
            await asyncio.sleep(2)
    
    yield engine
    
    # Cleanup
    await engine.dispose()


# Redis client fixture using real Docker containers
@pytest.fixture(scope="session") 
async def test_redis_client(test_settings: Settings) -> AsyncGenerator[RedisClient, None]:
    """Create test Redis client using real Docker containers."""
    redis_client = RedisClient()
    
    # Configure Redis client for testing
    import redis.asyncio as redis
    redis_client._redis = redis.from_url(
        test_settings.REDIS_URL, 
        decode_responses=test_settings.REDIS_DECODE_RESPONSES,
        retry_on_timeout=True,
        socket_keepalive=True,
    )
    
    # Wait for Redis to be ready
    max_retries = 30
    for attempt in range(max_retries):
        try:
            await redis_client.ping()
            break
        except Exception as e:
            if attempt == max_retries - 1:
                raise e
            await asyncio.sleep(1)
    
    yield redis_client
    
    # Cleanup
    try:
        await redis_client.flushdb()
    except Exception:
        pass
    await redis_client.disconnect()


# Database session fixture
@pytest.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create database session for testing."""
    AsyncSessionLocal = sessionmaker(
        test_engine, 
        class_=AsyncSession, 
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )
    
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.rollback()
            await session.close()


# Override dependencies for testing
def override_get_db(db_session: AsyncSession):
    """Override database dependency for testing."""
    async def _get_db():
        yield db_session
    return _get_db


def override_get_redis(test_redis_client: RedisClient):
    """Override Redis dependency for testing."""
    def _get_redis():
        return test_redis_client
    return _get_redis


# FastAPI test client fixture
@pytest.fixture
async def async_client(
    db_session: AsyncSession,
    test_redis_client: RedisClient
) -> AsyncGenerator[AsyncClient, None]:
    """Create async HTTP client for testing."""
    # Override dependencies
    app.dependency_overrides[get_db] = override_get_db(db_session)
    app.dependency_overrides[get_redis] = override_get_redis(test_redis_client)
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client
    
    # Clear overrides
    app.dependency_overrides.clear()


# Test data fixtures
@pytest.fixture
async def test_role(db_session: AsyncSession) -> Role:
    """Create test role."""
    role = Role(name="test_role", description="Test role for testing")
    db_session.add(role)
    await db_session.commit()
    await db_session.refresh(role)
    return role


@pytest.fixture
async def admin_role(db_session: AsyncSession) -> Role:
    """Create admin role."""
    role = Role(name="admin", description="Administrator role")
    db_session.add(role)
    await db_session.commit()
    await db_session.refresh(role)
    return role


@pytest.fixture
async def test_scope(db_session: AsyncSession) -> Scope:
    """Create test scope."""
    scope = Scope(
        name="read:test",
        description="Read test resources",
        resource="test"
    )
    db_session.add(scope)
    await db_session.commit()
    await db_session.refresh(scope)
    return scope


@pytest.fixture
async def service_api_scope(db_session: AsyncSession) -> Scope:
    """Create service API scope."""
    scope = Scope(
        name="service:api",
        description="Service API access",
        resource="api"
    )
    db_session.add(scope)
    await db_session.commit()
    await db_session.refresh(scope)
    return scope


@pytest.fixture
async def admin_scope(db_session: AsyncSession) -> Scope:
    """Create admin scope."""
    scope = Scope(
        name="admin:users",
        description="Manage users",
        resource="users"
    )
    db_session.add(scope)
    await db_session.commit()
    await db_session.refresh(scope)
    return scope


@pytest.fixture
async def admin_tokens_scope(db_session: AsyncSession) -> Scope:
    """Create admin tokens scope."""
    scope = Scope(
        name="admin:tokens",
        description="Manage tokens",
        resource="tokens"
    )
    db_session.add(scope)
    await db_session.commit()
    await db_session.refresh(scope)
    return scope


@pytest.fixture
async def test_user(db_session: AsyncSession, test_role: Role) -> User:
    """Create test user."""
    user = User(
        username="testuser",
        email="test@example.com",
        password_hash=hash_password("TestPassword123!"),
        first_name="Test",
        last_name="User",
        is_active=True,
    )
    user.roles.append(test_role)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def admin_user(db_session: AsyncSession, admin_role: Role) -> User:
    """Create admin user."""
    user = User(
        username="admin",
        email="admin@example.com",
        password_hash=hash_password("AdminPassword123!"),
        first_name="Admin",
        last_name="User",
        is_active=True,
    )
    user.roles.append(admin_role)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def disabled_user(db_session: AsyncSession) -> User:
    """Create disabled user."""
    user = User(
        username="disabled",
        email="disabled@example.com",
        password_hash=hash_password("DisabledPassword123!"),
        is_active=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def test_users(db_session: AsyncSession, test_role: Role, admin_role: Role) -> list[User]:
    """Create multiple test users."""
    users = []
    
    # Create test user with unique email
    test_user = User(
        username="testuser_bulk",
        email="testuser_bulk@example.com",
        password_hash=hash_password("TestPassword123!"),
        first_name="Test",
        last_name="User",
        is_active=True,
    )
    test_user.roles.append(test_role)
    users.append(test_user)
    
    # Create admin user with unique email
    admin_user = User(
        username="admin_bulk",
        email="admin_bulk@example.com",
        password_hash=hash_password("AdminPassword123!"),
        first_name="Admin",
        last_name="User",
        is_active=True,
    )
    admin_user.roles.append(admin_role)
    users.append(admin_user)
    
    # Create additional test users
    for i in range(3):
        user = User(
            username=f"user{i}",
            email=f"user{i}@example.com",
            password_hash=hash_password(f"Password{i}123!"),
            first_name=f"User{i}",
            last_name="Test",
            is_active=True,
        )
        user.roles.append(test_role)
        users.append(user)
    
    # Add all users to session
    for user in users:
        db_session.add(user)
    
    await db_session.commit()
    
    # Refresh all users
    for user in users:
        await db_session.refresh(user)
    
    return users


@pytest.fixture
async def test_service_client(db_session: AsyncSession, test_scope: Scope, service_api_scope: Scope) -> ServiceClient:
    """Create test service client."""
    client = ServiceClient(
        client_id="test-service",
        client_secret_hash=hash_password("test-secret"),
        name="Test Service",
        description="Test service client",
        is_active=True,
        access_token_lifetime=3600,
    )
    client.scopes.append(test_scope)
    client.scopes.append(service_api_scope)
    db_session.add(client)
    await db_session.commit()
    await db_session.refresh(client)
    return client


@pytest.fixture
async def disabled_service_client(db_session: AsyncSession) -> ServiceClient:
    """Create disabled service client."""
    client = ServiceClient(
        client_id="disabled-service",
        client_secret_hash=hash_password("disabled-secret"),
        name="Disabled Service",
        is_active=False,
    )
    db_session.add(client)
    await db_session.commit()
    await db_session.refresh(client)
    return client


# Token fixtures
@pytest.fixture
def test_access_token(test_user: User) -> str:
    """Create test access token."""
    return jwt_service.create_access_token(
        subject=str(test_user.id),
        scopes=["read:test", "admin:tokens"],
        audience=["test-api"],
        username=test_user.username,
        email=test_user.email,
    )


@pytest.fixture
def admin_access_token(admin_user: User) -> str:
    """Create admin access token."""
    return jwt_service.create_access_token(
        subject=str(admin_user.id),
        scopes=["admin:users"],
        audience=["test-api"],
        roles=["admin"],
        username=admin_user.username,
        email=admin_user.email,
    )


@pytest.fixture
def user_access_token(test_user: User) -> str:
    """Create regular user access token."""
    return jwt_service.create_access_token(
        subject=str(test_user.id),
        scopes=["read:test"],
        audience=["test-api"],
        username=test_user.username,
        email=test_user.email,
    )


# Helper function to convert UUIDs to strings for JSON serialization
def uuid_to_str(obj):
    """Convert UUID objects to strings for JSON serialization."""
    import uuid
    if isinstance(obj, uuid.UUID):
        return str(obj)
    elif isinstance(obj, list):
        return [uuid_to_str(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: uuid_to_str(value) for key, value in obj.items()}
    return obj


@pytest.fixture
def test_refresh_token(test_user: User) -> str:
    """Create test refresh token."""
    return jwt_service.create_refresh_token(
        subject=str(test_user.id),
        username=test_user.username,
    )


@pytest.fixture
def test_service_token(test_service_client: ServiceClient) -> str:
    """Create test service token."""
    return jwt_service.create_service_token(
        client_id=test_service_client.client_id,
        scopes=["read:test"],
        audience=["test-api"],
    )


@pytest.fixture
def expired_token() -> str:
    """Create expired token for testing."""
    from datetime import datetime, timedelta
    import jwt
    
    payload = {
        "sub": "test-user-id",
        "exp": datetime.utcnow() - timedelta(hours=1),  # Expired 1 hour ago
        "iat": datetime.utcnow() - timedelta(hours=2),
        "type": "access",
    }
    
    return jwt.encode(payload, "test-secret", algorithm="HS256")


# Authentication headers fixtures
@pytest.fixture
def auth_headers(test_access_token: str) -> dict:
    """Create authentication headers."""
    return {"Authorization": f"Bearer {test_access_token}"}


@pytest.fixture
def admin_auth_headers(admin_access_token: str) -> dict:
    """Create admin authentication headers."""
    return {"Authorization": f"Bearer {admin_access_token}"}


@pytest.fixture
def service_auth_headers(test_service_token: str) -> dict:
    """Create service authentication headers."""
    return {"Authorization": f"Bearer {test_service_token}"}


# Test data cleanup fixture
@pytest.fixture(autouse=True)
async def cleanup_database(db_session: AsyncSession):
    """Clean up database after each test."""
    yield
    
    try:
        # Rollback any pending transactions first
        await db_session.rollback()
        
        # Clean up test data in correct order (respecting foreign key constraints)
        await db_session.execute(text("DELETE FROM refresh_tokens"))
        await db_session.execute(text("DELETE FROM user_roles"))
        await db_session.execute(text("DELETE FROM role_scopes"))
        await db_session.execute(text("DELETE FROM service_client_scopes"))
        await db_session.execute(text("DELETE FROM users"))
        await db_session.execute(text("DELETE FROM roles"))
        await db_session.execute(text("DELETE FROM scopes"))
        await db_session.execute(text("DELETE FROM service_clients"))
        await db_session.commit()
    except Exception:
        # If cleanup fails, rollback and continue
        await db_session.rollback()


# Redis cleanup fixture
@pytest.fixture(autouse=True)
async def cleanup_redis(test_redis_client: RedisClient):
    """Clean up Redis after each test."""
    yield
    
    try:
        # Clear all Redis data
        await test_redis_client.flushdb()
    except Exception:
        # If cleanup fails, continue
        pass


# Pytest configuration
def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "security: mark test as a security test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "performance: mark test as performance test"
    )


# Async test configuration
pytest_plugins = ("pytest_asyncio",)