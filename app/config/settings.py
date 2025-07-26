"""Application settings and configuration."""

import secrets
from typing import List, Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    # Application
    APP_NAME: str = "Keystone Authentication API"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://keystone:password@localhost:5432/keystone"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 0
    DATABASE_ECHO: bool = False

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DECODE_RESPONSES: bool = True

    # JWT Configuration
    JWT_SECRET_KEY: str = secrets.token_urlsafe(32)
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "keystone-auth"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    SERVICE_TOKEN_EXPIRE_MINUTES: int = 15

    # Security
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_MAX_LENGTH: int = 128
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_PREVENT_REUSE_COUNT: int = 5
    PASSWORD_MAX_AGE_DAYS: int = 90

    # Rate Limiting
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_REGISTER: str = "3/hour"
    RATE_LIMIT_API: str = "100/minute"
    RATE_LIMIT_REFRESH: str = "10/minute"
    RATE_LIMIT_SERVICE_TOKEN: str = "20/minute"

    # Account Lockout
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    ALLOWED_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    ALLOWED_HEADERS: List[str] = ["*"]
    ALLOW_CREDENTIALS: bool = True
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1", "*"]

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # json or text
    LOG_FILE: Optional[str] = None

    # Monitoring
    ENABLE_METRICS: bool = True
    METRICS_PATH: str = "/metrics"

    # Cache Configuration
    CACHE_TOKEN_PREFIX: str = "keystone:token:"
    CACHE_SESSION_PREFIX: str = "keystone:session:"
    CACHE_RATE_LIMIT_PREFIX: str = "keystone:rate:"
    CACHE_USER_PREFIX: str = "keystone:user:"
    CACHE_DEFAULT_TTL: int = 3600  # 1 hour

    # Default Roles and Scopes
    DEFAULT_USER_ROLE: str = "user"
    ADMIN_ROLE: str = "admin"
    SERVICE_ROLE: str = "service"

    # API Configuration
    API_V1_PREFIX: str = "/api/v1"
    DOCS_URL: Optional[str] = "/docs"
    REDOC_URL: Optional[str] = "/redoc"
    OPENAPI_URL: Optional[str] = "/openapi.json"

    class Config:
        """Pydantic configuration."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"

    def __init__(self, **kwargs):
        """Initialize settings with production overrides."""
        super().__init__(**kwargs)
        
        # Disable docs in production
        if self.ENVIRONMENT == "production":
            self.DOCS_URL = None
            self.REDOC_URL = None
            self.OPENAPI_URL = None
            self.DEBUG = False
            self.DATABASE_ECHO = False

    @property
    def database_url_sync(self) -> str:
        """Get synchronous database URL for Alembic."""
        return self.DATABASE_URL.replace("+asyncpg", "")

    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.ENVIRONMENT == "development"

    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.ENVIRONMENT == "production"

    @property
    def is_testing(self) -> bool:
        """Check if running in testing mode."""
        return self.ENVIRONMENT == "testing"


# Global settings instance
settings = Settings()