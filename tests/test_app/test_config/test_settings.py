"""Tests for application settings configuration."""

import pytest
import os
from unittest.mock import patch, MagicMock
from pydantic import ValidationError

from app.config.settings import Settings, get_settings


class TestSettingsValidation:
    """Test settings validation and parsing."""

    def test_settings_default_values(self):
        """Test settings with default values."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }, clear=True):
            settings = Settings()
            
            # Test default values
            assert settings.app_name == "Keystone Auth"
            assert settings.debug is False
            assert settings.environment == "production"
            assert settings.api_v1_prefix == "/api/v1"
            assert settings.jwt_algorithm == "HS256"
            assert settings.access_token_expire_minutes == 30
            assert settings.refresh_token_expire_days == 7

    def test_settings_from_environment(self):
        """Test settings loaded from environment variables."""
        env_vars = {
            "APP_NAME": "Test Auth Service",
            "DEBUG": "true",
            "ENVIRONMENT": "development",
            "API_V1_PREFIX": "/api/test/v1",
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/1",
            "JWT_SECRET_KEY": "test-jwt-secret-key-for-testing-32chars",
            "JWT_ALGORITHM": "HS512",
            "ACCESS_TOKEN_EXPIRE_MINUTES": "60",
            "REFRESH_TOKEN_EXPIRE_DAYS": "14",
            "PASSWORD_MIN_LENGTH": "12",
            "MAX_LOGIN_ATTEMPTS": "3",
            "ACCOUNT_LOCKOUT_MINUTES": "60",
            "RATE_LIMIT_PER_MINUTE": "30",
            "CORS_ORIGINS": "http://localhost:3000,https://example.com",
            "ALLOWED_HOSTS": "localhost,example.com",
        }
        
        with patch.dict(os.environ, env_vars, clear=True):
            settings = Settings()
            
            assert settings.app_name == "Test Auth Service"
            assert settings.debug is True
            assert settings.environment == "development"
            assert settings.api_v1_prefix == "/api/test/v1"
            assert settings.jwt_secret_key == "test-jwt-secret-key-for-testing-32chars"
            assert settings.jwt_algorithm == "HS512"
            assert settings.access_token_expire_minutes == 60
            assert settings.refresh_token_expire_days == 14
            assert settings.password_min_length == 12
            assert settings.max_login_attempts == 3
            assert settings.account_lockout_minutes == 60
            assert settings.rate_limit_per_minute == 30
            assert "http://localhost:3000" in settings.cors_origins
            assert "https://example.com" in settings.cors_origins
            assert "localhost" in settings.allowed_hosts
            assert "example.com" in settings.allowed_hosts

    def test_settings_required_fields_missing(self):
        """Test settings validation with missing required fields."""
        # Test missing DATABASE_URL
        with patch.dict(os.environ, {
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key"
        }, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()
            
            assert "database_url" in str(exc_info.value).lower()

        # Test missing REDIS_URL
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "JWT_SECRET_KEY": "test-secret-key"
        }, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()
            
            assert "redis_url" in str(exc_info.value).lower()

        # Test missing JWT_SECRET_KEY
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0"
        }, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()
            
            assert "jwt_secret_key" in str(exc_info.value).lower()

    def test_settings_invalid_values(self):
        """Test settings validation with invalid values."""
        base_env = {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key"
        }
        
        # Test invalid boolean
        with patch.dict(os.environ, {**base_env, "DEBUG": "invalid"}, clear=True):
            with pytest.raises(ValidationError):
                Settings()

        # Test invalid integer
        with patch.dict(os.environ, {**base_env, "ACCESS_TOKEN_EXPIRE_MINUTES": "invalid"}, clear=True):
            with pytest.raises(ValidationError):
                Settings()

        # Test invalid URL
        with patch.dict(os.environ, {**base_env, "DATABASE_URL": "invalid-url"}, clear=True):
            with pytest.raises(ValidationError):
                Settings()

    def test_settings_jwt_secret_key_validation(self):
        """Test JWT secret key validation."""
        base_env = {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0"
        }
        
        # Test short secret key
        with patch.dict(os.environ, {**base_env, "JWT_SECRET_KEY": "short"}, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()
            
            assert "at least 32 characters" in str(exc_info.value).lower()

        # Test valid secret key
        with patch.dict(os.environ, {**base_env, "JWT_SECRET_KEY": "a" * 32}, clear=True):
            settings = Settings()
            assert len(settings.jwt_secret_key) == 32

    def test_settings_password_policy_validation(self):
        """Test password policy settings validation."""
        base_env = {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }
        
        # Test minimum password length
        with patch.dict(os.environ, {**base_env, "PASSWORD_MIN_LENGTH": "4"}, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()
            
            assert "password_min_length" in str(exc_info.value).lower()

        # Test valid password length
        with patch.dict(os.environ, {**base_env, "PASSWORD_MIN_LENGTH": "8"}, clear=True):
            settings = Settings()
            assert settings.password_min_length == 8

    def test_settings_security_validation(self):
        """Test security-related settings validation."""
        base_env = {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }
        
        # Test max login attempts
        with patch.dict(os.environ, {**base_env, "MAX_LOGIN_ATTEMPTS": "0"}, clear=True):
            with pytest.raises(ValidationError):
                Settings()

        # Test account lockout minutes
        with patch.dict(os.environ, {**base_env, "ACCOUNT_LOCKOUT_MINUTES": "-1"}, clear=True):
            with pytest.raises(ValidationError):
                Settings()

        # Test rate limit
        with patch.dict(os.environ, {**base_env, "RATE_LIMIT_PER_MINUTE": "0"}, clear=True):
            with pytest.raises(ValidationError):
                Settings()

    def test_settings_cors_origins_parsing(self):
        """Test CORS origins parsing."""
        base_env = {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }
        
        # Test single origin
        with patch.dict(os.environ, {**base_env, "CORS_ORIGINS": "http://localhost:3000"}, clear=True):
            settings = Settings()
            assert settings.cors_origins == ["http://localhost:3000"]

        # Test multiple origins
        with patch.dict(os.environ, {**base_env, "CORS_ORIGINS": "http://localhost:3000,https://example.com,https://app.example.com"}, clear=True):
            settings = Settings()
            expected_origins = ["http://localhost:3000", "https://example.com", "https://app.example.com"]
            assert settings.cors_origins == expected_origins

        # Test empty origins
        with patch.dict(os.environ, {**base_env, "CORS_ORIGINS": ""}, clear=True):
            settings = Settings()
            assert settings.cors_origins == []

    def test_settings_allowed_hosts_parsing(self):
        """Test allowed hosts parsing."""
        base_env = {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }
        
        # Test single host
        with patch.dict(os.environ, {**base_env, "ALLOWED_HOSTS": "localhost"}, clear=True):
            settings = Settings()
            assert settings.allowed_hosts == ["localhost"]

        # Test multiple hosts
        with patch.dict(os.environ, {**base_env, "ALLOWED_HOSTS": "localhost,example.com,api.example.com"}, clear=True):
            settings = Settings()
            expected_hosts = ["localhost", "example.com", "api.example.com"]
            assert settings.allowed_hosts == expected_hosts

    def test_settings_database_url_parsing(self):
        """Test database URL parsing and validation."""
        base_env = {
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }
        
        # Test PostgreSQL URL
        with patch.dict(os.environ, {**base_env, "DATABASE_URL": "postgresql://user:pass@localhost:5432/dbname"}, clear=True):
            settings = Settings()
            assert "postgresql://" in settings.database_url

        # Test PostgreSQL with SSL
        with patch.dict(os.environ, {**base_env, "DATABASE_URL": "postgresql://user:pass@localhost:5432/dbname?sslmode=require"}, clear=True):
            settings = Settings()
            assert "sslmode=require" in settings.database_url

    def test_settings_redis_url_parsing(self):
        """Test Redis URL parsing and validation."""
        base_env = {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }
        
        # Test Redis URL with database
        with patch.dict(os.environ, {**base_env, "REDIS_URL": "redis://localhost:6379/1"}, clear=True):
            settings = Settings()
            assert settings.redis_url == "redis://localhost:6379/1"

        # Test Redis URL with password
        with patch.dict(os.environ, {**base_env, "REDIS_URL": "redis://:password@localhost:6379/0"}, clear=True):
            settings = Settings()
            assert "password" in settings.redis_url

    def test_settings_environment_specific_defaults(self):
        """Test environment-specific default values."""
        base_env = {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }
        
        # Test development environment
        with patch.dict(os.environ, {**base_env, "ENVIRONMENT": "development"}, clear=True):
            settings = Settings()
            assert settings.environment == "development"
            # Development might have different defaults

        # Test testing environment
        with patch.dict(os.environ, {**base_env, "ENVIRONMENT": "testing"}, clear=True):
            settings = Settings()
            assert settings.environment == "testing"

        # Test production environment
        with patch.dict(os.environ, {**base_env, "ENVIRONMENT": "production"}, clear=True):
            settings = Settings()
            assert settings.environment == "production"


class TestSettingsProperties:
    """Test computed properties and methods."""

    def test_settings_is_development(self):
        """Test is_development property."""
        base_env = {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }
        
        with patch.dict(os.environ, {**base_env, "ENVIRONMENT": "development"}, clear=True):
            settings = Settings()
            assert settings.is_development is True

        with patch.dict(os.environ, {**base_env, "ENVIRONMENT": "production"}, clear=True):
            settings = Settings()
            assert settings.is_development is False

    def test_settings_is_testing(self):
        """Test is_testing property."""
        base_env = {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }
        
        with patch.dict(os.environ, {**base_env, "ENVIRONMENT": "testing"}, clear=True):
            settings = Settings()
            assert settings.is_testing is True

        with patch.dict(os.environ, {**base_env, "ENVIRONMENT": "production"}, clear=True):
            settings = Settings()
            assert settings.is_testing is False

    def test_settings_database_config(self):
        """Test database configuration extraction."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://user:pass@localhost:5432/testdb",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }, clear=True):
            settings = Settings()
            
            # Test that database URL is properly formatted
            assert "postgresql://" in settings.database_url
            assert "testdb" in settings.database_url

    def test_settings_redis_config(self):
        """Test Redis configuration extraction."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/2",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }, clear=True):
            settings = Settings()
            
            # Test that Redis URL is properly formatted
            assert "redis://" in settings.redis_url
            assert "/2" in settings.redis_url


class TestGetSettings:
    """Test the get_settings function and caching."""

    def test_get_settings_returns_settings_instance(self):
        """Test that get_settings returns a Settings instance."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }, clear=True):
            settings = get_settings()
            assert isinstance(settings, Settings)

    def test_get_settings_caching(self):
        """Test that get_settings caches the settings instance."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }, clear=True):
            # Clear the cache first
            get_settings.cache_clear()
            
            settings1 = get_settings()
            settings2 = get_settings()
            
            # Should return the same instance due to caching
            assert settings1 is settings2

    def test_get_settings_cache_clear(self):
        """Test that cache can be cleared."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }, clear=True):
            settings1 = get_settings()
            get_settings.cache_clear()
            settings2 = get_settings()
            
            # Should return different instances after cache clear
            assert settings1 is not settings2


class TestSettingsIntegration:
    """Test settings integration with other components."""

    def test_settings_with_fastapi_app(self):
        """Test settings integration with FastAPI application."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars",
            "DEBUG": "true",
            "ENVIRONMENT": "development",
            "CORS_ORIGINS": "http://localhost:3000"
        }, clear=True):
            settings = Settings()
            
            # Test that settings can be used for FastAPI configuration
            assert settings.debug is True
            assert len(settings.cors_origins) > 0
            assert settings.api_v1_prefix.startswith("/")

    def test_settings_security_configuration(self):
        """Test security-related settings configuration."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars",
            "MAX_LOGIN_ATTEMPTS": "5",
            "ACCOUNT_LOCKOUT_MINUTES": "30",
            "RATE_LIMIT_PER_MINUTE": "60"
        }, clear=True):
            settings = Settings()
            
            # Test security settings
            assert settings.max_login_attempts == 5
            assert settings.account_lockout_minutes == 30
            assert settings.rate_limit_per_minute == 60
            assert len(settings.jwt_secret_key) >= 32

    def test_settings_token_configuration(self):
        """Test token-related settings configuration."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars",
            "ACCESS_TOKEN_EXPIRE_MINUTES": "15",
            "REFRESH_TOKEN_EXPIRE_DAYS": "30",
            "JWT_ALGORITHM": "HS256"
        }, clear=True):
            settings = Settings()
            
            # Test token settings
            assert settings.access_token_expire_minutes == 15
            assert settings.refresh_token_expire_days == 30
            assert settings.jwt_algorithm == "HS256"

    @pytest.mark.parametrize("env_name,expected_value", [
        ("development", True),
        ("testing", False),
        ("production", False),
    ])
    def test_settings_environment_detection(self, env_name, expected_value):
        """Test environment detection logic."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars",
            "ENVIRONMENT": env_name
        }, clear=True):
            settings = Settings()
            assert settings.is_development == expected_value
            assert settings.environment == env_name


class TestSettingsErrorHandling:
    """Test error handling in settings."""

    def test_settings_validation_error_messages(self):
        """Test that validation errors provide helpful messages."""
        # Test with completely empty environment
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()
            
            error_str = str(exc_info.value)
            assert "database_url" in error_str.lower()
            assert "redis_url" in error_str.lower()
            assert "jwt_secret_key" in error_str.lower()

    def test_settings_type_conversion_errors(self):
        """Test type conversion error handling."""
        base_env = {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }
        
        # Test invalid integer conversion
        with patch.dict(os.environ, {**base_env, "ACCESS_TOKEN_EXPIRE_MINUTES": "not_a_number"}, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()
            
            assert "access_token_expire_minutes" in str(exc_info.value).lower()

    def test_settings_url_validation_errors(self):
        """Test URL validation error handling."""
        base_env = {
            "REDIS_URL": "redis://localhost:6379/0",
            "JWT_SECRET_KEY": "test-secret-key-for-testing-32chars"
        }
        
        # Test invalid database URL
        with patch.dict(os.environ, {**base_env, "DATABASE_URL": "not-a-valid-url"}, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()
            
            assert "database_url" in str(exc_info.value).lower()