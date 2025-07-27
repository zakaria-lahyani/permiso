# Service-to-Service Authentication Tutorial

## Overview

This tutorial demonstrates how to implement secure service-to-service authentication using the permiso authentication system. Service-to-service authentication uses the OAuth2 Client Credentials flow, allowing microservices to authenticate and authorize API calls between each other.

## Prerequisites

- permiso authentication service running
- Service client registered in the system
- Basic understanding of OAuth2 and JWT tokens

## Quick Start

### 1. Register Your Service Client

First, register your service as a client in the permiso system:

```python
# Example service client registration
service_client = {
    "client_id": "payment-service",
    "name": "Payment Processing Service",
    "description": "Handles payment transactions and billing",
    "client_type": "confidential",
    "is_trusted": True,
    "access_token_lifetime": 7200,  # 2 hours
    "rate_limit_per_minute": 120,
    "scopes": ["read:users", "write:transactions", "admin:billing"]
}
```

### 2. Obtain Service Token

Use the client credentials flow to get an access token:

```python
import httpx
import asyncio
from typing import Optional

class ServiceAuthClient:
    def __init__(self, auth_base_url: str, client_id: str, client_secret: str):
        self.auth_base_url = auth_base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token: Optional[str] = None
        self.token_expires_at: Optional[float] = None

    async def get_access_token(self) -> str:
        """Get or refresh access token using client credentials flow."""
        import time
        
        # Check if current token is still valid
        if (self.access_token and self.token_expires_at and 
            time.time() < self.token_expires_at - 60):  # 60s buffer
            return self.access_token

        # Request new token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.auth_base_url}/auth/service-token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "read:users write:transactions"  # Optional
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code != 200:
                raise Exception(f"Token request failed: {response.text}")
            
            token_data = response.json()
            self.access_token = token_data["access_token"]
            self.token_expires_at = time.time() + token_data["expires_in"]
            
            return self.access_token

    async def make_authenticated_request(
        self, 
        method: str, 
        url: str, 
        **kwargs
    ) -> httpx.Response:
        """Make an authenticated HTTP request to another service."""
        token = await self.get_access_token()
        
        headers = kwargs.get("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        kwargs["headers"] = headers
        
        async with httpx.AsyncClient() as client:
            return await client.request(method, url, **kwargs)

# Usage example
auth_client = ServiceAuthClient(
    auth_base_url="https://auth.yourcompany.com",
    client_id="payment-service",
    client_secret="your-client-secret"
)

# Make authenticated request to another service
response = await auth_client.make_authenticated_request(
    "GET",
    "https://user-service.yourcompany.com/api/v1/users/123"
)
```

### 3. Protect Your Service Endpoints

Protect your service endpoints to accept tokens from other services:

```python
from fastapi import FastAPI, Depends, HTTPException
from app.core.security import get_current_service_client, require_scopes

app = FastAPI()

@app.get("/api/v1/transactions")
async def get_transactions(
    # Accept service tokens with required scope
    payload: dict = Depends(require_scopes(["read:transactions"]))
):
    """Endpoint accessible by services with read:transactions scope."""
    client_id = payload.get("client_id")
    return {
        "transactions": [...],
        "requested_by": client_id
    }

@app.post("/api/v1/transactions")
async def create_transaction(
    transaction_data: dict,
    # Require write permissions
    payload: dict = Depends(require_scopes(["write:transactions"]))
):
    """Endpoint for creating transactions."""
    return {"transaction_id": "txn_123", "status": "created"}

@app.get("/api/v1/admin/billing")
async def get_billing_data(
    # Admin-only endpoint
    service_client = Depends(get_current_service_client)
):
    """Admin endpoint - requires trusted service client."""
    if not service_client.is_trusted:
        raise HTTPException(status_code=403, detail="Trusted client required")
    
    return {"billing_data": [...]}
```

## Advanced Patterns

### 1. Service Client Factory

Create a reusable factory for service authentication:

```python
import os
from typing import Dict, Optional
from dataclasses import dataclass

@dataclass
class ServiceConfig:
    client_id: str
    client_secret: str
    auth_base_url: str
    scopes: Optional[str] = None

class ServiceClientFactory:
    _clients: Dict[str, ServiceAuthClient] = {}
    
    @classmethod
    def get_client(cls, service_name: str) -> ServiceAuthClient:
        """Get or create service auth client."""
        if service_name not in cls._clients:
            config = cls._get_config(service_name)
            cls._clients[service_name] = ServiceAuthClient(
                auth_base_url=config.auth_base_url,
                client_id=config.client_id,
                client_secret=config.client_secret
            )
        return cls._clients[service_name]
    
    @classmethod
    def _get_config(cls, service_name: str) -> ServiceConfig:
        """Load configuration for service."""
        return ServiceConfig(
            client_id=os.getenv(f"{service_name.upper()}_CLIENT_ID"),
            client_secret=os.getenv(f"{service_name.upper()}_CLIENT_SECRET"),
            auth_base_url=os.getenv("AUTH_SERVICE_URL"),
            scopes=os.getenv(f"{service_name.upper()}_SCOPES")
        )

# Usage
payment_client = ServiceClientFactory.get_client("payment")
user_client = ServiceClientFactory.get_client("user")
```

### 2. Middleware for Automatic Token Refresh

```python
import httpx
from typing import Callable

class ServiceAuthMiddleware:
    def __init__(self, auth_client: ServiceAuthClient):
        self.auth_client = auth_client

    async def __call__(self, request: httpx.Request) -> httpx.Request:
        """Add authentication header to outgoing requests."""
        token = await self.auth_client.get_access_token()
        request.headers["Authorization"] = f"Bearer {token}"
        return request

# Usage with httpx client
async def create_http_client() -> httpx.AsyncClient:
    auth_client = ServiceClientFactory.get_client("payment")
    middleware = ServiceAuthMiddleware(auth_client)
    
    return httpx.AsyncClient(
        auth=middleware,
        timeout=30.0
    )
```

### 3. Retry Logic with Token Refresh

```python
import asyncio
from typing import Any, Dict

class ServiceClient:
    def __init__(self, auth_client: ServiceAuthClient):
        self.auth_client = auth_client

    async def call_service(
        self, 
        method: str, 
        url: str, 
        max_retries: int = 2,
        **kwargs
    ) -> Dict[str, Any]:
        """Call service with automatic token refresh on 401."""
        
        for attempt in range(max_retries + 1):
            try:
                response = await self.auth_client.make_authenticated_request(
                    method, url, **kwargs
                )
                
                if response.status_code == 401 and attempt < max_retries:
                    # Token might be expired, force refresh
                    self.auth_client.access_token = None
                    continue
                
                response.raise_for_status()
                return response.json()
                
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401 and attempt < max_retries:
                    # Force token refresh and retry
                    self.auth_client.access_token = None
                    await asyncio.sleep(0.1 * (2 ** attempt))  # Exponential backoff
                    continue
                raise
                
        raise Exception(f"Failed to call {url} after {max_retries} retries")
```

## Configuration Examples

### Environment Variables

```bash
# Service Authentication
AUTH_SERVICE_URL=https://auth.yourcompany.com
PAYMENT_CLIENT_ID=payment-service
PAYMENT_CLIENT_SECRET=your-secret-key
PAYMENT_SCOPES=read:users write:transactions

# Service Discovery
USER_SERVICE_URL=https://user-service.yourcompany.com
BILLING_SERVICE_URL=https://billing-service.yourcompany.com
```

### Docker Compose

```yaml
version: '3.8'
services:
  payment-service:
    image: payment-service:latest
    environment:
      - AUTH_SERVICE_URL=http://auth-service:8000
      - PAYMENT_CLIENT_ID=payment-service
      - PAYMENT_CLIENT_SECRET=${PAYMENT_CLIENT_SECRET}
      - USER_SERVICE_URL=http://user-service:8000
    depends_on:
      - auth-service
      - user-service

  user-service:
    image: user-service:latest
    environment:
      - AUTH_SERVICE_URL=http://auth-service:8000
      - USER_CLIENT_ID=user-service
      - USER_CLIENT_SECRET=${USER_CLIENT_SECRET}
    depends_on:
      - auth-service
```

## Security Best Practices

### 1. Client Secret Management

```python
import os
from cryptography.fernet import Fernet

class SecretManager:
    def __init__(self):
        self.cipher = Fernet(os.getenv("ENCRYPTION_KEY").encode())
    
    def get_client_secret(self, service_name: str) -> str:
        """Get decrypted client secret."""
        encrypted_secret = os.getenv(f"{service_name.upper()}_CLIENT_SECRET_ENCRYPTED")
        return self.cipher.decrypt(encrypted_secret.encode()).decode()

# Usage
secret_manager = SecretManager()
client_secret = secret_manager.get_client_secret("payment")
```

### 2. Token Caching and Storage

```python
import redis
import json
from typing import Optional

class TokenCache:
    def __init__(self, redis_url: str):
        self.redis = redis.from_url(redis_url)
    
    def get_token(self, client_id: str) -> Optional[str]:
        """Get cached token."""
        token_data = self.redis.get(f"service_token:{client_id}")
        if token_data:
            data = json.loads(token_data)
            import time
            if time.time() < data["expires_at"]:
                return data["access_token"]
        return None
    
    def set_token(self, client_id: str, access_token: str, expires_in: int):
        """Cache token with expiration."""
        import time
        data = {
            "access_token": access_token,
            "expires_at": time.time() + expires_in - 60  # 60s buffer
        }
        self.redis.setex(
            f"service_token:{client_id}",
            expires_in - 60,
            json.dumps(data)
        )
```

### 3. Request Signing (Optional)

```python
import hmac
import hashlib
import time
from typing import Dict

class RequestSigner:
    def __init__(self, client_secret: str):
        self.client_secret = client_secret
    
    def sign_request(self, method: str, url: str, body: str = "") -> Dict[str, str]:
        """Sign request for additional security."""
        timestamp = str(int(time.time()))
        message = f"{method}|{url}|{body}|{timestamp}"
        
        signature = hmac.new(
            self.client_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return {
            "X-Timestamp": timestamp,
            "X-Signature": signature
        }

# Usage in service client
class SecureServiceClient(ServiceAuthClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.signer = RequestSigner(self.client_secret)
    
    async def make_authenticated_request(self, method: str, url: str, **kwargs):
        # Add signature headers
        body = kwargs.get("json", "")
        if isinstance(body, dict):
            body = json.dumps(body)
        
        signature_headers = self.signer.sign_request(method, url, body)
        
        headers = kwargs.get("headers", {})
        headers.update(signature_headers)
        kwargs["headers"] = headers
        
        return await super().make_authenticated_request(method, url, **kwargs)
```

## Testing Service Authentication

### Unit Tests

```python
import pytest
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_service_auth_client():
    with patch("httpx.AsyncClient") as mock_client:
        # Mock token response
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test-token",
            "expires_in": 3600
        }
        mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
        
        auth_client = ServiceAuthClient(
            auth_base_url="http://test",
            client_id="test-client",
            client_secret="test-secret"
        )
        
        token = await auth_client.get_access_token()
        assert token == "test-token"

@pytest.mark.asyncio
async def test_authenticated_request():
    auth_client = ServiceAuthClient(
        auth_base_url="http://test",
        client_id="test-client",
        client_secret="test-secret"
    )
    
    with patch.object(auth_client, "get_access_token", return_value="test-token"):
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_client.return_value.__aenter__.return_value.request.return_value = mock_response
            
            response = await auth_client.make_authenticated_request("GET", "http://test/api")
            
            # Verify Authorization header was added
            call_args = mock_client.return_value.__aenter__.return_value.request.call_args
            headers = call_args[1]["headers"]
            assert headers["Authorization"] == "Bearer test-token"
```

### Integration Tests

```python
@pytest.mark.asyncio
async def test_service_to_service_flow():
    """Test complete service-to-service authentication flow."""
    
    # Start test services
    async with TestAuthService() as auth_service:
        async with TestUserService() as user_service:
            
            # Create service client
            auth_client = ServiceAuthClient(
                auth_base_url=auth_service.base_url,
                client_id="test-service",
                client_secret="test-secret"
            )
            
            # Test token acquisition
            token = await auth_client.get_access_token()
            assert token is not None
            
            # Test authenticated request
            response = await auth_client.make_authenticated_request(
                "GET",
                f"{user_service.base_url}/api/v1/users"
            )
            
            assert response.status_code == 200
            data = response.json()
            assert "users" in data
```

## Troubleshooting

### Common Issues

1. **401 Unauthorized**
   - Check client credentials
   - Verify token hasn't expired
   - Ensure proper Authorization header format

2. **403 Forbidden**
   - Verify client has required scopes
   - Check if client is trusted (for admin endpoints)
   - Validate scope inheritance rules

3. **Token Refresh Issues**
   - Implement proper retry logic
   - Handle token expiration gracefully
   - Use appropriate buffer time

### Debug Logging

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class DebugServiceAuthClient(ServiceAuthClient):
    async def get_access_token(self) -> str:
        logger.debug(f"Requesting token for client: {self.client_id}")
        token = await super().get_access_token()
        logger.debug(f"Received token: {token[:20]}...")
        return token
    
    async def make_authenticated_request(self, method: str, url: str, **kwargs):
        logger.debug(f"Making {method} request to {url}")
        response = await super().make_authenticated_request(method, url, **kwargs)
        logger.debug(f"Response status: {response.status_code}")
        return response
```

This tutorial provides a comprehensive guide for implementing secure service-to-service authentication using the permiso authentication system. The patterns and examples can be adapted to your specific microservice architecture and security requirements.