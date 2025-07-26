# Keystone FastAPI Project Structure & Technical Specifications

## 📁 Project Directory Structure

```
keystone/
├── app/
│   ├── __init__.py
│   ├── main.py                     # FastAPI application entry point
│   ├── config/
│   │   ├── __init__.py
│   │   ├── settings.py             # Application configuration
│   │   ├── database.py             # Database configuration
│   │   └── redis.py                # Redis configuration
│   ├── api/
│   │   ├── __init__.py
│   │   ├── deps.py                 # Dependency injection
│   │   └── v1/
│   │       ├── __init__.py
│   │       ├── auth.py             # Authentication endpoints
│   │       ├── users.py            # User management endpoints
│   │       └── admin.py            # Admin endpoints
│   ├── core/
│   │   ├── __init__.py
│   │   ├── security.py             # Security utilities
│   │   ├── jwt.py                  # JWT token handling
│   │   ├── password.py             # Password utilities
│   │   └── exceptions.py           # Custom exceptions
│   ├── services/
│   │   ├── __init__.py
│   │   ├── auth_service.py         # Authentication business logic
│   │   ├── user_service.py         # User management logic
│   │   ├── token_service.py        # Token management
│   │   ├── cache_service.py        # Redis caching
│   │   └── rate_limit_service.py   # Rate limiting logic
│   ├── models/
│   │   ├── __init__.py
│   │   ├── base.py                 # Base model class
│   │   ├── user.py                 # User model
│   │   ├── role.py                 # Role model
│   │   ├── scope.py                # Scope model
│   │   ├── service_client.py       # Service client model
│   │   └── refresh_token.py        # Refresh token model
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── auth.py                 # Authentication schemas
│   │   ├── user.py                 # User schemas
│   │   ├── token.py                # Token schemas
│   │   └── common.py               # Common schemas
│   ├── crud/
│   │   ├── __init__.py
│   │   ├── base.py                 # Base CRUD operations
│   │   ├── user.py                 # User CRUD operations
│   │   ├── role.py                 # Role CRUD operations
│   │   ├── scope.py                # Scope CRUD operations
│   │   └── service_client.py       # Service client CRUD
│   ├── middleware/
│   │   ├── __init__.py
│   │   ├── auth.py                 # Authentication middleware
│   │   ├── rate_limit.py           # Rate limiting middleware
│   │   └── logging.py              # Logging middleware
│   └── utils/
│       ├── __init__.py
│       ├── validators.py           # Input validators
│       ├── helpers.py              # Helper functions
│       └── constants.py            # Application constants
├── tests/
│   ├── __init__.py
│   ├── conftest.py                 # Pytest configuration
│   ├── test_auth.py                # Authentication tests
│   ├── test_users.py               # User management tests
│   ├── test_tokens.py              # Token management tests
│   ├── test_security.py            # Security tests
│   └── integration/
│       ├── __init__.py
│       ├── test_api.py             # API integration tests
│       └── test_database.py        # Database integration tests
├── alembic/
│   ├── versions/                   # Database migration files
│   ├── env.py                      # Alembic environment
│   └── script.py.mako              # Migration template
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── docker-compose.dev.yml
│   └── init-scripts/
│       └── init-db.sql
├── scripts/
│   ├── start.sh                    # Application startup script
│   ├── test.sh                     # Test execution script
│   └── migrate.sh                  # Database migration script
├── docs/
│   ├── API.md
│   ├── DEPLOYMENT.md
│   └── SECURITY.md
├── requirements/
│   ├── base.txt                    # Base dependencies
│   ├── dev.txt                     # Development dependencies
│   └── prod.txt                    # Production dependencies
├── pyproject.toml                  # Poetry configuration
├── requirements.txt                # Pip requirements
├── alembic.ini                     # Alembic configuration
├── pytest.ini                      # Pytest configuration
├── .env.example                    # Environment variables example
├── README.md
└── .gitignore
```

## 🔧 Dependencies Configuration

### pyproject.toml (Poetry)
```toml
[tool.poetry]
name = "keystone-auth"
version = "1.0.0"
description = "Centralized Authentication and Authorization System"
authors = ["Your Name <your.email@example.com>"]
readme = "README.md"

[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.104.1"
uvicorn = {extras = ["standard"], version = "^0.24.0"}
pydantic = {extras = ["email"], version = "^2.5.0"}
pydantic-settings = "^2.1.0"
sqlalchemy = {extras = ["asyncio"], version = "^2.0.23"}
alembic = "^1.13.0"
asyncpg = "^0.29.0"
aioredis = "^2.0.1"
passlib = {extras = ["argon2"], version = "^1.7.4"}
pyjwt = {extras = ["crypto"], version = "^2.8.0"}
python-multipart = "^0.0.6"
slowapi = "^0.1.9"
structlog = "^23.2.0"
prometheus-client = "^0.19.0"
httpx = "^0.25.2"

[tool.poetry.group.dev.dependencies]
pytest = "^7.4.3"
pytest-asyncio = "^0.21.1"
pytest-cov = "^4.1.0"
black = "^23.11.0"
isort = "^5.12.0"
flake8 = "^6.1.0"
mypy = "^1.7.1"
pre-commit = "^3.6.0"
testcontainers = "^3.7.1"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"

[tool.black]
line-length = 88
target-version = ['py311']
include = '\.pyi?$'

[tool.isort]
profile = "black"
multi_line_output = 3
line_length = 88

[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
```

### requirements.txt (Alternative to Poetry)
```txt
# Core Framework
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic[email]==2.5.0
pydantic-settings==2.1.0

# Database
sqlalchemy[asyncio]==2.0.23
alembic==1.13.0
asyncpg==0.29.0

# Caching
aioredis==2.0.1

# Security
passlib[argon2]==1.7.4
pyjwt[crypto]==2.8.0
python-multipart==0.0.6

# Middleware & Utils
slowapi==0.1.9
structlog==23.2.0
prometheus-client==0.19.0
httpx==0.25.2

# Development
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
black==23.11.0
isort==5.12.0
flake8==6.1.0
mypy==1.7.1
testcontainers==3.7.1
```

## ⚙️ Configuration Files

### app/config/settings.py
```python
from pydantic_settings import BaseSettings
from typing import List, Optional
import secrets

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Keystone Authentication API"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://keystone:password@localhost/keystone"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 0
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: Optional[str] = None
    
    # JWT
    JWT_SECRET_KEY: str = secrets.token_urlsafe(32)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    
    # Security
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    
    # Rate Limiting
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_REGISTER: str = "3/hour"
    RATE_LIMIT_API: str = "100/minute"
    
    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]
    ALLOWED_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE"]
    ALLOWED_HEADERS: List[str] = ["*"]
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
```

### app/main.py
```python
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog
import time

from app.config.settings import settings
from app.api.v1 import auth, users, admin
from app.core.exceptions import AuthenticationError, AuthorizationError
from app.middleware.logging import LoggingMiddleware
from app.middleware.rate_limit import RateLimitMiddleware

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Centralized Authentication and Authorization System",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=settings.ALLOWED_METHODS,
    allow_headers=settings.ALLOWED_HEADERS,
)

# Add custom middleware
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware)

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["authentication"])
app.include_router(users.router, prefix="/api/v1/users", tags=["users"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["admin"])

# Exception handlers
@app.exception_handler(AuthenticationError)
async def authentication_exception_handler(request: Request, exc: AuthenticationError):
    return JSONResponse(
        status_code=401,
        content={
            "error": "authentication_failed",
            "error_description": str(exc),
            "timestamp": time.time()
        }
    )

@app.exception_handler(AuthorizationError)
async def authorization_exception_handler(request: Request, exc: AuthorizationError):
    return JSONResponse(
        status_code=403,
        content={
            "error": "authorization_failed",
            "error_description": str(exc),
            "timestamp": time.time()
        }
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": time.time()}

# Metrics endpoint
@app.get("/metrics")
async def metrics():
    from prometheus_client import generate_latest
    return Response(generate_latest(), media_type="text/plain")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_config=None  # Use structlog instead
    )
```

## 🗄️ Database Models

### app/models/base.py
```python
from sqlalchemy import Column, DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
import uuid

Base = declarative_base()

class BaseModel(Base):
    __abstract__ = True
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
```

### app/models/user.py
```python
from sqlalchemy import Column, String, Boolean, DateTime, Table, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from .base import BaseModel, Base

# Association tables
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id'), primary_key=True),
    Column('role_id', UUID(as_uuid=True), ForeignKey('roles.id'), primary_key=True)
)

class User(BaseModel):
    __tablename__ = "users"
    
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(50))
    last_name = Column(String(50))
    enabled = Column(Boolean, default=True)
    last_login = Column(DateTime(timezone=True))
    
    # Relationships
    roles = relationship("Role", secondary=user_roles, back_populates="users")
    refresh_tokens = relationship("RefreshToken", back_populates="user")
    
    def has_role(self, role_name: str) -> bool:
        return any(role.name == role_name for role in self.roles)
    
    def get_scopes(self) -> list[str]:
        scopes = set()
        for role in self.roles:
            for scope in role.scopes:
                scopes.add(scope.name)
        return list(scopes)
```

## 📝 Pydantic Schemas

### app/schemas/auth.py
```python
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
from datetime import datetime

class LoginRequest(BaseModel):
    username: EmailStr
    password: str = Field(..., min_length=1)
    grant_type: str = Field(default="password")
    client_id: Optional[str] = None
    scope: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_in: int
    scope: Optional[str] = None
    jti: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str
    grant_type: str = Field(default="refresh_token")
    client_id: Optional[str] = None

class ClientCredentialsRequest(BaseModel):
    client_id: str
    client_secret: str
    grant_type: str = Field(default="client_credentials")
    scope: Optional[str] = None
    audience: Optional[List[str]] = None

class RevokeTokenRequest(BaseModel):
    token: str
    token_type_hint: Optional[str] = None
```

## 🔐 Security Implementation

### app/core/jwt.py
```python
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import jwt
from app.config.settings import settings
from app.core.exceptions import AuthenticationError

class JWTService:
    def __init__(self):
        self.secret_key = settings.JWT_SECRET_KEY
        self.algorithm = settings.JWT_ALGORITHM
    
    def create_access_token(
        self,
        subject: str,
        scopes: List[str],
        audience: List[str],
        expires_delta: Optional[timedelta] = None,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        payload = {
            "iss": "keystone-auth",
            "aud": audience,
            "sub": subject,
            "exp": expire,
            "iat": datetime.utcnow(),
            "nbf": datetime.utcnow(),
            "jti": str(uuid4()),
            "type": "access",
            "scopes": scopes
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def decode_token(self, token: str) -> Dict[str, Any]:
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                options={"verify_aud": False}  # We'll verify audience manually
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid token")
    
    def verify_token(
        self, 
        token: str, 
        expected_audience: Optional[str] = None
    ) -> Dict[str, Any]:
        payload = self.decode_token(token)
        
        # Verify audience if specified
        if expected_audience:
            audiences = payload.get("aud", [])
            if expected_audience not in audiences:
                raise AuthenticationError("Invalid token audience")
        
        return payload

jwt_service = JWTService()
```

## 🐳 Docker Configuration

### Dockerfile
```dockerfile
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### docker-compose.yml
```yaml
version: '3.8'

services:
  keystone-app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://keystone:${DB_PASSWORD}@postgres:5432/keystone
      - REDIS_URL=redis://redis:6379/0
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - ./logs:/app/logs
    networks:
      - keystone-network

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: keystone
      POSTGRES_USER: keystone
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./docker/init-scripts:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keystone"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - keystone-network

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - keystone-network

volumes:
  postgres_data:
  redis_data:

networks:
  keystone-network:
    driver: bridge
```

## 🧪 Testing Configuration

### pytest.ini
```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    -v
    --tb=short
    --strict-markers
    --disable-warnings
    --cov=app
    --cov-report=term-missing
    --cov-report=html
    --cov-fail-under=80
asyncio_mode = auto
```

### tests/conftest.py
```python
import pytest
import asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

from app.main import app
from app.config.database import get_db
from app.models.base import Base

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def postgres_container():
    with PostgresContainer("postgres:15-alpine") as postgres:
        yield postgres

@pytest.fixture(scope="session")
async def redis_container():
    with RedisContainer("redis:7-alpine") as redis:
        yield redis

@pytest.fixture
async def async_client():
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

@pytest.fixture
async def db_session(postgres_container):
    engine = create_async_engine(postgres_container.get_connection_url())
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    AsyncSessionLocal = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with AsyncSessionLocal() as session:
        yield session
```

This FastAPI-based project structure provides a modern, scalable foundation for the Keystone authentication system with excellent async support, comprehensive testing, and production-ready configuration.