# 🏗️ Comprehensive Service Integration Guide - Part 2

This is the continuation of the comprehensive integration guide. This part covers the remaining sections including Docker deployment, environment management, testing, and complete examples.

## 🐳 Docker Deployment (Continued)

### 2. Environment Configuration

```bash
# .env.integration
# Database
POSTGRES_PASSWORD=secure-postgres-password

# Redis
REDIS_PASSWORD=secure-redis-password

# JWT Configuration
JWT_SECRET_KEY=your-super-secure-jwt-secret-key-for-production

# Service Secrets
DASHBOARD_CLIENT_SECRET=dashboard-client-secret-key
MT5_SERVICE_CLIENT_SECRET=mt5-service-client-secret-key

# MT5 Configuration
MT5_SERVER=your-mt5-server.com
MT5_LOGIN=12345
MT5_PASSWORD=mt5-account-password

# Network Configuration
ALLOWED_ORIGINS=https://trading.yourdomain.com,https://admin.yourdomain.com
CORS_ORIGINS=https://trading.yourdomain.com

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Security
RATE_LIMIT_LOGIN=5/minute
RATE_LIMIT_API=100/minute
```

### 3. Nginx Configuration

```nginx
# nginx/nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream permiso-auth {
        server permiso-auth:8000;
    }
    
    upstream mt5-api {
        server mt5-api:8001;
    }
    
    upstream trading-dashboard {
        server trading-dashboard:80;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;

    server {
        listen 80;
        server_name trading.yourdomain.com;
        
        # Security headers
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;

        # Frontend (Trading Dashboard)
        location / {
            proxy_pass http://trading-dashboard;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Authentication API
        location /api/v1/auth/ {
            limit_req zone=auth burst=20 nodelay;
            
            proxy_pass http://permiso-auth;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # CORS headers for auth endpoints
            add_header Access-Control-Allow-Origin "https://trading.yourdomain.com" always;
            add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
            add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
            add_header Access-Control-Allow-Credentials "true" always;
            
            if ($request_method = 'OPTIONS') {
                return 204;
            }
        }

        # Other Permiso API endpoints
        location /api/v1/ {
            limit_req zone=api burst=50 nodelay;
            
            proxy_pass http://permiso-auth;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # MT5 API endpoints
        location /mt5/api/ {
            limit_req zone=api burst=100 nodelay;
            
            rewrite ^/mt5/api/(.*)$ /api/$1 break;
            proxy_pass http://mt5-api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health checks
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
```

### 4. Service Dockerfiles

```dockerfile
# mt5-service/Dockerfile
FROM python:3.11-slim as base

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app

USER app

EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
```

```dockerfile
# frontend/Dockerfile
# Build stage
FROM node:18-alpine as build

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM nginx:alpine as production

# Copy built application
COPY --from=build /app/build /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

## 🔧 Environment Management

### 1. Environment-Specific Configurations

```python
# shared/config/environments.py
from typing import Dict, Any
from dataclasses import dataclass

@dataclass
class EnvironmentConfig:
    """Environment-specific configuration."""
    
    # Service URLs
    permiso_auth_url: str
    mt5_api_url: str
    dashboard_url: str
    
    # Database
    database_url: str
    redis_url: str
    
    # JWT Configuration
    jwt_algorithm: str
    jwt_issuer: str
    access_token_expire_minutes: int
    service_token_expire_minutes: int
    
    # Security
    allowed_origins: list
    rate_limits: Dict[str, str]
    
    # Logging
    log_level: str
    log_format: str

# Environment configurations
ENVIRONMENTS = {
    "development": EnvironmentConfig(
        permiso_auth_url="http://localhost:8000",
        mt5_api_url="http://localhost:8001",
        dashboard_url="http://localhost:3000",
        database_url="postgresql+asyncpg://permiso:dev@localhost:5432/permiso_dev",
        redis_url="redis://localhost:6379/0",
        jwt_algorithm="HS256",
        jwt_issuer="permiso-auth-dev",
        access_token_expire_minutes=60,
        service_token_expire_minutes=120,
        allowed_origins=["http://localhost:3000", "http://localhost:8080"],
        rate_limits={
            "login": "10/minute",
            "api": "1000/minute",
            "service_token": "100/minute"
        },
        log_level="DEBUG",
        log_format="text"
    ),
    
    "staging": EnvironmentConfig(
        permiso_auth_url="https://auth-staging.yourdomain.com",
        mt5_api_url="https://mt5-api-staging.yourdomain.com",
        dashboard_url="https://trading-staging.yourdomain.com",
        database_url="postgresql+asyncpg://permiso:${POSTGRES_PASSWORD}@postgres-staging:5432/permiso_staging",
        redis_url="redis://:${REDIS_PASSWORD}@redis-staging:6379/0",
        jwt_algorithm="RS256",
        jwt_issuer="permiso-auth-staging",
        access_token_expire_minutes=30,
        service_token_expire_minutes=60,
        allowed_origins=["https://trading-staging.yourdomain.com"],
        rate_limits={
            "login": "5/minute",
            "api": "200/minute",
            "service_token": "50/minute"
        },
        log_level="INFO",
        log_format="json"
    ),
    
    "production": EnvironmentConfig(
        permiso_auth_url="https://auth.yourdomain.com",
        mt5_api_url="https://mt5-api.yourdomain.com",
        dashboard_url="https://trading.yourdomain.com",
        database_url="postgresql+asyncpg://permiso:${POSTGRES_PASSWORD}@postgres:5432/permiso",
        redis_url="redis://:${REDIS_PASSWORD}@redis:6379/0",
        jwt_algorithm="RS256",
        jwt_issuer="permiso-auth",
        access_token_expire_minutes=15,
        service_token_expire_minutes=30,
        allowed_origins=["https://trading.yourdomain.com"],
        rate_limits={
            "login": "5/minute",
            "api": "100/minute",
            "service_token": "20/minute"
        },
        log_level="INFO",
        log_format="json"
    )
}

def get_environment_config(env_name: str) -> EnvironmentConfig:
    """Get configuration for specified environment."""
    if env_name not in ENVIRONMENTS:
        raise ValueError(f"Unknown environment: {env_name}")
    
    return ENVIRONMENTS[env_name]
```

### 2. Secrets Management

```python
# shared/config/secrets.py
import os
import json
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet
import boto3
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

class SecretsManager:
    """Centralized secrets management."""
    
    def __init__(self, provider: str = "env"):
        self.provider = provider
        self._secrets_cache: Dict[str, str] = {}
        
        if provider == "aws":
            self.aws_client = boto3.client('secretsmanager')
        elif provider == "azure":
            vault_url = os.getenv("AZURE_KEY_VAULT_URL")
            credential = DefaultAzureCredential()
            self.azure_client = SecretClient(vault_url=vault_url, credential=credential)
        elif provider == "encrypted":
            key = os.getenv("ENCRYPTION_KEY", "").encode()
            self.cipher = Fernet(key) if key else None
    
    def get_secret(self, secret_name: str) -> Optional[str]:
        """Get secret value."""
        # Check cache first
        if secret_name in self._secrets_cache:
            return self._secrets_cache[secret_name]
        
        secret_value = None
        
        if self.provider == "env":
            secret_value = os.getenv(secret_name)
        
        elif self.provider == "aws":
            try:
                response = self.aws_client.get_secret_value(SecretId=secret_name)
                secret_value = response['SecretString']
            except Exception as e:
                print(f"Failed to get secret from AWS: {e}")
        
        elif self.provider == "azure":
            try:
                secret = self.azure_client.get_secret(secret_name)
                secret_value = secret.value
            except Exception as e:
                print(f"Failed to get secret from Azure: {e}")
        
        elif self.provider == "encrypted":
            encrypted_value = os.getenv(f"{secret_name}_ENCRYPTED")
            if encrypted_value and self.cipher:
                try:
                    secret_value = self.cipher.decrypt(encrypted_value.encode()).decode()
                except Exception as e:
                    print(f"Failed to decrypt secret: {e}")
        
        # Cache the secret
        if secret_value:
            self._secrets_cache[secret_name] = secret_value
        
        return secret_value
    
    def get_database_url(self) -> str:
        """Get database URL with password from secrets."""
        base_url = os.getenv("DATABASE_URL_TEMPLATE", "postgresql+asyncpg://permiso:{password}@postgres:5432/permiso")
        password = self.get_secret("POSTGRES_PASSWORD")
        return base_url.format(password=password)
    
    def get_redis_url(self) -> str:
        """Get Redis URL with password from secrets."""
        base_url = os.getenv("REDIS_URL_TEMPLATE", "redis://:{password}@redis:6379/0")
        password = self.get_secret("REDIS_PASSWORD")
        return base_url.format(password=password)
    
    def get_jwt_secret(self) -> str:
        """Get JWT secret key."""
        return self.get_secret("JWT_SECRET_KEY")
    
    def get_service_credentials(self, service_name: str) -> Dict[str, str]:
        """Get service client credentials."""
        return {
            "client_id": f"{service_name}-service",
            "client_secret": self.get_secret(f"{service_name.upper()}_CLIENT_SECRET")
        }

# Global secrets manager instance
secrets_manager = SecretsManager(
    provider=os.getenv("SECRETS_PROVIDER", "env")
)
```

### 3. Configuration Validation

```python
# shared/config/validation.py
from pydantic import BaseModel, validator, Field
from typing import List, Dict, Optional
import re

class ServiceConfig(BaseModel):
    """Service configuration with validation."""
    
    service_name: str = Field(..., min_length=1, max_length=50)
    version: str = Field(..., regex=r'^\d+\.\d+\.\d+$')
    host: str = Field(default="0.0.0.0")
    port: int = Field(..., ge=1, le=65535)
    
    # URLs
    permiso_auth_url: str = Field(..., regex=r'^https?://.+')
    database_url: str = Field(..., regex=r'^postgresql\+asyncpg://.+')
    redis_url: str = Field(..., regex=r'^redis://.+')
    
    # JWT Configuration
    jwt_algorithm: str = Field(..., regex=r'^(HS256|RS256)$')
    jwt_issuer: str = Field(..., min_length=1)
    access_token_expire_minutes: int = Field(..., ge=1, le=1440)
    service_token_expire_minutes: int = Field(..., ge=1, le=1440)
    
    # Security
    allowed_origins: List[str] = Field(default=[])
    rate_limits: Dict[str, str] = Field(default={})
    
    # Logging
    log_level: str = Field(..., regex=r'^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$')
    log_format: str = Field(..., regex=r'^(text|json)$')
    
    @validator('allowed_origins')
    def validate_origins(cls, v):
        """Validate CORS origins."""
        url_pattern = re.compile(r'^https?://[a-zA-Z0-9.-]+(?::[0-9]+)?$')
        for origin in v:
            if origin != "*" and not url_pattern.match(origin):
                raise ValueError(f"Invalid origin format: {origin}")
        return v
    
    @validator('rate_limits')
    def validate_rate_limits(cls, v):
        """Validate rate limit format."""
        rate_pattern = re.compile(r'^\d+/(second|minute|hour|day)$')
        for key, limit in v.items():
            if not rate_pattern.match(limit):
                raise ValueError(f"Invalid rate limit format for {key}: {limit}")
        return v

def validate_environment_config(config_dict: Dict) -> ServiceConfig:
    """Validate environment configuration."""
    try:
        return ServiceConfig(**config_dict)
    except Exception as e:
        raise ValueError(f"Configuration validation failed: {e}")
```

## 🧪 Testing Integration

### 1. Integration Test Setup

```python
# tests/integration/test_service_integration.py
import pytest
import asyncio
import httpx
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer
from testcontainers.compose import DockerCompose
import time

from shared.config.secrets import SecretsManager
from services.auth_client import PermisoAuthClient

class TestServiceIntegration:
    """Integration tests for service-to-service authentication."""
    
    @pytest.fixture(scope="class")
    async def test_environment(self):
        """Set up test environment with containers."""
        
        # Start containers
        with DockerCompose(".", compose_file_name="docker-compose.test.yml") as compose:
            # Wait for services to be ready
            await self._wait_for_service("http://localhost:8000/health", timeout=60)
            await self._wait_for_service("http://localhost:8001/health", timeout=60)
            
            yield {
                "auth_url": "http://localhost:8000",
                "mt5_api_url": "http://localhost:8001",
                "compose": compose
            }
    
    async def _wait_for_service(self, url: str, timeout: int = 30):
        """Wait for service to be ready."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(url, timeout=5.0)
                    if response.status_code == 200:
                        return
            except Exception:
                pass
            
            await asyncio.sleep(1)
        
        raise TimeoutError(f"Service at {url} did not become ready within {timeout} seconds")
    
    @pytest.mark.asyncio
    async def test_complete_authentication_flow(self, test_environment):
        """Test complete authentication flow from client registration to API access."""
        
        auth_url = test_environment["auth_url"]
        mt5_api_url = test_environment["mt5_api_url"]
        
        # Step 1: Register service client (using admin credentials)
        admin_token = await self._get_admin_token(auth_url)
        client_credentials = await self._register_test_client(auth_url, admin_token)
        
        # Step 2: Get service token using client credentials
        auth_client = PermisoAuthClient(
            auth_base_url=auth_url,
            client_id=client_credentials["client_id"],
            client_secret=client_credentials["client_secret"]
        )
        
        service_token = await auth_client.get_service_token(
            scopes=["trade:read", "account:read"]
        )
        
        assert service_token is not None
        assert len(service_token) > 50  # JWT tokens are long
        
        # Step 3: Use service token to access MT5 API
        response = await auth_client.make_authenticated_request(
            "GET",
            f"{mt5_api_url}/api/v1/trades",
            scopes=["trade:read"]
        )
        
        assert response.status_code == 200
        trades_data = response.json()
        assert isinstance(trades_data, list)
        
        # Step 4: Test scope enforcement
        with pytest.raises(Exception):  # Should fail without proper scope
            await auth_client.make_authenticated_request(
                "POST",
                f"{mt5_api_url}/api/v1/trades",
                json={
                    "symbol": "EURUSD",
                    "volume": 0.1,
                    "trade_type": "buy"
                }
                # Missing trade:open scope
            )
    
    async def _get_admin_token(self, auth_url: str) -> str:
        """Get admin token for test setup."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{auth_url}/api/v1/auth/token",
                data={
                    "username": "admin",
                    "password": "admin123"  # Test admin credentials
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get admin token: {response.text}")
            
            token_data = response.json()
            return token_data["access_token"]
    
    async def _register_test_client(self, auth_url: str, admin_token: str) -> dict:
        """Register test service client."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{auth_url}/api/v1/admin/service-clients",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={
                    "client_id": "test-integration-client",
                    "name": "Integration Test Client",
                    "description": "Client for integration testing",
                    "client_type": "confidential",
                    "is_trusted": True,
                    "access_token_lifetime": 3600,
                    "scope_ids": ["trade:read", "trade:open", "account:read"]
                }
            )
            
            if response.status_code != 201:
                raise Exception(f"Failed to register test client: {response.text}")
            
            client_data = response.json()
            return {
                "client_id": client_data["client"]["client_id"],
                "client_secret": client_data["client_secret"]
            }
    
    @pytest.mark.asyncio
    async def test_token_caching_and_refresh(self, test_environment):
        """Test token caching and automatic refresh."""
        
        auth_url = test_environment["auth_url"]
        
        # Get client credentials
        admin_token = await self._get_admin_token(auth_url)
        client_credentials = await self._register_test_client(auth_url, admin_token)
        
        auth_client = PermisoAuthClient(
            auth_base_url=auth_url,
            client_id=client_credentials["client_id"],
            client_secret=client_credentials["client_secret"]
        )
        
        # First token request
        token1 = await auth_client.get_service_token()
        
        # Second request should return cached token
        token2 = await auth_client.get_service_token()
        assert token1 == token2
        
        # Force refresh should return new token
        token3 = await auth_client.get_service_token(force_refresh=True)
        assert token3 != token1
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, test_environment):
        """Test rate limiting enforcement."""
        
        auth_url = test_environment["auth_url"]
        
        # Make rapid requests to trigger rate limiting
        async with httpx.AsyncClient() as client:
            responses = []
            
            for _ in range(10):  # Exceed rate limit
                response = await client.post(
                    f"{auth_url}/api/v1/auth/token",
                    data={
                        "username": "invalid",
                        "password": "invalid"
                    }
                )
                responses.append(response.status_code)
            
            # Should eventually get 429 (Too Many Requests)
            assert 429 in responses
    
    @pytest.mark.asyncio
    async def test_token_revocation(self, test_environment):
        """Test token revocation functionality."""
        
        auth_url = test_environment["auth_url"]
        mt5_api_url = test_environment["mt5_api_url"]
        
        # Get service token
        admin_token = await self._get_admin_token(auth_url)
        client_credentials = await self._register_test_client(auth_url, admin_token)
        
        auth_client = PermisoAuthClient(
            auth_base_url=auth_url,
            client_id=client_credentials["client_id"],
            client_secret=client_credentials["client_secret"]
        )
        
        service_token = await auth_client.get_service_token()
        
        # Use token successfully
        response = await auth_client.make_authenticated_request(
            "GET",
            f"{mt5_api_url}/api/v1/trades"
        )
        assert response.status_code == 200
        
        # Revoke token
        async with httpx.AsyncClient() as client:
            revoke_response = await client.post(
                f"{auth_url}/api/v1/auth/revoke",
                headers={"Authorization": f"Bearer {service_token}"},
                json={"token": service_token}
            )
            assert revoke_response.status_code == 200
        
        # Token should no longer work
        with pytest.raises(Exception):
            await auth_client.make_authenticated_request(
                "GET",
                f"{mt5_api_url}/api/v1/trades"
            )
```

### 2. Load Testing

```python
# tests/load/test_auth_performance.py
import asyncio
import time
import statistics
from typing import List, Dict, Any
import httpx
import pytest

class AuthPerformanceTest:
    """Performance tests for authentication system."""
    
    def __init__(self, auth_url: str, client_credentials: Dict[str, str]):
        self.auth_url = auth_url
        self.client_credentials = client_credentials
        self.results: List[Dict[str, Any]] = []
    
    async def test_token_generation_performance(self, concurrent_requests: int = 10, total_requests: int = 100):
        """Test token generation performance under load."""
        
        async def make_token_request() -> Dict[str, Any]:
            start_time = time.perf_counter()
            
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(
                        f"{self.auth_url}/api/v1/auth/service-token",
                        data={
                            "client_id": self.client_credentials["client_id"],
                            "client_secret": self.client_credentials["client_secret"],
                            "scope": "trade:read account:read"
                        }
                    )
                    
                    end_time = time.perf_counter()
                    duration = end_time - start_time
                    
                    return {
                        "success": response.status_code == 200,
                        "status_code": response.status_code,
                        "duration": duration,
                        "timestamp": start_time
                    }
            
            except Exception as e:
                end_time = time.perf_counter()
                return {
                    "success": False,
                    "status_code": 0,
                    "duration": end_time - start_time,
                    "error": str(e),
                    "timestamp": start_time
                }
        
        # Run concurrent requests
        semaphore = asyncio.Semaphore(concurrent_requests)
        
        async def limited_request():
            async with semaphore:
                return await make_token_request()
        
        # Execute all requests
        tasks = [limited_request() for _ in range(total_requests)]
        results = await asyncio.gather(*tasks)
        
        # Analyze results
        successful_requests = [r for r in results if r["success"]]
        failed_requests = [r for r in results if not r["success"]]
        
        if successful_requests:
            durations = [r["duration"] for r in successful_requests]
            
            performance_stats = {
                "total_requests": total_requests,
                "successful_requests": len(successful_requests),
                "failed_requests": len(failed_requests),
                "success_rate": len(successful_requests) / total_requests * 100,
                "avg_response_time": statistics.mean(durations),
                "median_response_time": statistics.median(durations),
                "min_response_time": min(durations),
                "max_response_time": max(durations),
                "p95_response_time": self._percentile(durations, 95),
                "p99_response_time": self._percentile(durations, 99),
                "requests_per_second": len(successful_requests) / max(durations) if durations else 0
            }
            
            return performance_stats
        
        return {"error": "No successful requests"}
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile of data."""
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile / 100)
        return sorted_data[min(index, len(sorted_data) - 1)]
    
    async def test_api_endpoint_performance(self, mt5_api_url: str, endpoint: str = "/api/v1/trades"):
        """Test API endpoint performance with authentication."""
        
        # Get service token first
        auth_client = PermisoAuthClient(
            auth_base_url=self.auth_url,
            client_id=self.client_credentials["client_id"],
            client_secret=self.client_credentials["client_secret"]
        )
        
        token = await auth_client.get_service_token(scopes=["trade:read"])
        
        async def make_api_request() -> Dict[str, Any]:
            start_time = time.perf_counter()
            
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(
                        f"{mt5_api_url}{endpoint}",
                        headers={"Authorization": f"Bearer {token}"}
                    )
                    
                    end_time = time.perf_counter()
                    
                    return {
                        "success": response.status_code == 200,
                        "status_code": response.status_code,
                        "duration": end_time - start_time,
                        "response_size": len(response.content)
                    }
            
            except Exception as e:
                end_time = time.perf_counter()
                return {
                    "success": False,
                    "duration": end_time - start_time,
                    "error": str(e)
                }
        
        # Run multiple requests
        tasks = [make_api_request() for _ in range(50)]
        results = await asyncio.gather(*tasks)
        
        successful_results = [r for r in results if r["success"]]
        
        if successful_results:
            durations = [r["duration"] for r in successful_results]
            
            return {
                "endpoint": endpoint,
                "total_requests": len(results),
                "successful_requests": len(successful_results),
                "avg_response_time": statistics.mean(durations),
                "median_response_time": statistics.median(durations),
                