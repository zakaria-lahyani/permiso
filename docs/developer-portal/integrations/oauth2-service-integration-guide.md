# 🏗️ OAuth2 Service-to-Service Integration Guide

A comprehensive guide for integrating Permiso Auth into a service-to-service architecture with practical examples, complete code implementations, and production-ready deployment strategies.

## 📖 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [Service Client Registration](#service-client-registration)
5. [OAuth2 Client Credentials Flow](#oauth2-client-credentials-flow)
6. [Protecting Services with JWT](#protecting-services-with-jwt)
7. [Client Implementation](#client-implementation)
8. [Docker Deployment](#docker-deployment)
9. [Environment Management](#environment-management)
10. [Testing](#testing)
11. [Monitoring & Troubleshooting](#monitoring--troubleshooting)
12. [Complete Example](#complete-example)
13. [Best Practices](#best-practices)

## 🎯 Overview

This guide demonstrates how to integrate Permiso Auth into a service-to-service architecture using OAuth2 client credentials flow. We'll build a complete trading system with:

- **Permiso Auth Service**: Centralized authentication and authorization
- **MT5 API Service**: Protected trading service with FastAPI
- **Trading Dashboard**: React client application
- **Docker Deployment**: Complete containerized setup

### Key Features Covered

✅ **OAuth2 Client Credentials Flow** - Service-to-service authentication  
✅ **JWT Token Management** - Secure token generation and validation  
✅ **Role-Based Access Control** - Granular permissions with scopes  
✅ **FastAPI Integration** - Dependency injection patterns  
✅ **Token Caching & Refresh** - Efficient token management  
✅ **Docker Deployment** - Production-ready containerization  
✅ **Comprehensive Testing** - Unit, integration, and load testing  
✅ **Monitoring & Auditing** - Security event tracking  

## 🏛️ Architecture

### System Components

```mermaid
graph TB
    subgraph "Client Applications"
        DASHBOARD[Trading Dashboard<br/>React App]
        MOBILE[Mobile App]
        EXTERNAL[External Clients]
    end
    
    subgraph "Authentication Layer"
        PERMISO[Permiso Auth Service<br/>:8000]
        subgraph "Auth Components"
            TOKEN_API[Token API]
            CLIENT_MGR[Client Management]
            JWT_SVC[JWT Service]
            SCOPE_MGR[Scope Management]
        end
    end
    
    subgraph "Business Services"
        MT5_API[MT5 API Service<br/>:8001]
        ACCOUNT_SVC[Account Service<br/>:8002]
        NOTIFY_SVC[Notification Service<br/>:8003]
    end
    
    subgraph "Data Layer"
        POSTGRES[(PostgreSQL<br/>Auth & User Data)]
        REDIS[(Redis<br/>Token Cache)]
        MT5_DB[(Trading Database)]
    end
    
    DASHBOARD -->|1. Get Service Token| PERMISO
    DASHBOARD -->|2. API Calls + JWT| MT5_API
    DASHBOARD -->|3. API Calls + JWT| ACCOUNT_SVC
    
    MT5_API -->|Validate JWT| PERMISO
    ACCOUNT_SVC -->|Validate JWT| PERMISO
    NOTIFY_SVC -->|Service-to-Service| PERMISO
    
    PERMISO --> POSTGRES
    PERMISO --> REDIS
    MT5_API --> MT5_DB
    
    style PERMISO fill:#e1f5fe
    style MT5_API fill:#f3e5f5
    style DASHBOARD fill:#e8f5e8
```

### Authentication Flow

```mermaid
sequenceDiagram
    participant Client as Trading Dashboard
    participant Auth as Permiso Auth
    participant MT5 as MT5 API Service
    participant Cache as Redis
    
    Note over Client,MT5: 1. Service Registration (One-time)
    Auth->>Auth: Register service clients
    Auth->>Auth: Assign scopes & permissions
    
    Note over Client,MT5: 2. Client Credentials Flow
    Client->>Auth: POST /auth/service-token<br/>{client_id, client_secret, scope}
    Auth->>Auth: Validate credentials
    Auth->>Auth: Generate JWT with scopes
    Auth->>Cache: Cache token metadata
    Auth-->>Client: {access_token, expires_in}
    
    Note over Client,MT5: 3. Protected API Access
    Client->>MT5: GET /api/v1/trades<br/>Authorization: Bearer <token>
    MT5->>MT5: Extract & validate JWT
    MT5->>Auth: Validate token (optional)
    Auth->>Cache: Check revocation
    Auth-->>MT5: Token valid
    MT5->>MT5: Check scopes
    MT5-->>Client: Protected resource
    
    Note over Client,MT5: 4. Token Refresh
    Client->>Auth: New token request
    Auth-->>Client: Fresh access token
```

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+
- Node.js 18+ (for frontend)
- Basic understanding of OAuth2 and JWT

### 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/your-org/permiso-auth.git
cd permiso-auth

# Copy environment template
cp .env.example .env.integration

# Edit environment variables
nano .env.integration
```

### 2. Start Services

```bash
# Start all services
docker-compose -f docker-compose.integration.yml up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f permiso-auth
docker-compose logs -f mt5-api
```

### 3. Initialize System

```bash
# Run setup script
python scripts/setup-services.py

# Test the integration
python scripts/test-integration.py
```

### 4. Access Services

- **Permiso Auth API**: http://localhost:8000
- **MT5 API Service**: http://localhost:8001  
- **Trading Dashboard**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs

## 🔐 Service Client Registration

### 1. Register MT5 API Service

```python
# Register via API
import httpx
import asyncio

async def register_mt5_service():
    async with httpx.AsyncClient() as client:
        # Get admin token first
        admin_response = await client.post(
            "http://localhost:8000/api/v1/auth/token",
            data={"username": "admin", "password": "admin123"}
        )
        admin_token = admin_response.json()["access_token"]
        
        # Register MT5 service
        service_config = {
            "client_id": "mt5-api-service",
            "name": "MT5 Trading API Service",
            "description": "MetaTrader 5 integration service",
            "client_type": "confidential",
            "is_trusted": True,
            "access_token_lifetime": 3600,  # 1 hour
            "rate_limit_per_minute": 300,
            "scope_ids": [
                "trade:open", "trade:close", "trade:modify", "trade:read",
                "account:read", "account:balance", "market:data", "service:mt5"
            ]
        }
        
        response = await client.post(
            "http://localhost:8000/api/v1/admin/service-clients",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=service_config
        )
        
        if response.status_code == 201:
            client_data = response.json()
            print(f"✅ Service registered successfully!")
            print(f"Client ID: {client_data['client']['client_id']}")
            print(f"Client Secret: {client_data['client_secret']}")
            print("⚠️ Store the client secret securely!")
            return client_data
        else:
            print(f"❌ Registration failed: {response.text}")

# Run registration
asyncio.run(register_mt5_service())
```

### 2. Register Trading Dashboard

```python
async def register_dashboard_client():
    # Similar to above but with different configuration
    client_config = {
        "client_id": "trading-dashboard",
        "name": "Trading Dashboard Web App",
        "description": "Web-based trading dashboard",
        "client_type": "confidential",
        "is_trusted": False,  # External-facing
        "access_token_lifetime": 1800,  # 30 minutes
        "rate_limit_per_minute": 120,
        "scope_ids": [
            "read:profile", "write:profile", "trade:read", 
            "trade:open", "account:read", "market:data"
        ]
    }
    # ... registration logic
```

### 3. Using CLI Tool

```bash
# Register service via CLI
permiso-cli register-client \
  --client-id mt5-api-service \
  --name "MT5 Trading API Service" \
  --type confidential \
  --trusted \
  --scopes "trade:open,trade:close,account:read,market:data"
```

## 🎫 OAuth2 Client Credentials Flow

### 1. Basic Token Request

```python
# services/auth_client.py
import httpx
import time
from typing import Optional, List
from dataclasses import dataclass

@dataclass
class TokenResponse:
    access_token: str
    token_type: str
    expires_in: int
    scope: Optional[str] = None
    expires_at: Optional[float] = None

class PermisoAuthClient:
    """Client for Permiso authentication service."""
    
    def __init__(self, auth_base_url: str, client_id: str, client_secret: str):
        self.auth_base_url = auth_base_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self._current_token: Optional[TokenResponse] = None
        
    async def get_service_token(self, scopes: Optional[List[str]] = None) -> str:
        """Get service access token using client credentials flow."""
        
        # Check if current token is still valid
        if self._is_token_valid():
            return self._current_token.access_token
        
        # Request new token
        scope_str = " ".join(scopes) if scopes else None
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.auth_base_url}/api/v1/auth/service-token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": scope_str
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code != 200:
                error_detail = response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text
                raise AuthenticationError(f"Token request failed: {error_detail}")
            
            token_data = response.json()
            
            self._current_token = TokenResponse(
                access_token=token_data["access_token"],
                token_type=token_data.get("token_type", "Bearer"),
                expires_in=token_data["expires_in"],
                scope=token_data.get("scope"),
                expires_at=time.time() + token_data["expires_in"]
            )
            
            return self._current_token.access_token
    
    def _is_token_valid(self) -> bool:
        """Check if current token is valid and not expired."""
        if not self._current_token:
            return False
        # Add 60-second buffer
        return time.time() < (self._current_token.expires_at - 60)
    
    async def make_authenticated_request(
        self, method: str, url: str, scopes: Optional[List[str]] = None, **kwargs
    ) -> httpx.Response:
        """Make authenticated HTTP request."""
        token = await self.get_service_token(scopes=scopes)
        
        headers = kwargs.get("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        kwargs["headers"] = headers
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            return await client.request(method, url, **kwargs)

class AuthenticationError(Exception):
    """Authentication-related error."""
    pass
```

### 2. Advanced Token Management

```python
# services/advanced_auth_client.py
import asyncio
import backoff
from typing import Optional, List
import structlog

logger = structlog.get_logger(__name__)

class AdvancedAuthClient(PermisoAuthClient):
    """Advanced authentication client with retry logic and caching."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_retries = kwargs.get('max_retries', 3)
        
    @backoff.on_exception(
        backoff.expo,
        (httpx.RequestError, AuthenticationError),
        max_tries=3,
        base=1,
        max_value=10
    )
    async def get_service_token_with_retry(self, scopes: Optional[List[str]] = None) -> str:
        """Get service token with exponential backoff retry."""
        return await self.get_service_token(scopes=scopes)
    
    async def make_authenticated_request_with_retry(
        self, method: str, url: str, scopes: Optional[List[str]] = None, 
        max_retries: int = 2, **kwargs
    ) -> httpx.Response:
        """Make authenticated request with automatic token refresh on 401."""
        
        for attempt in range(max_retries + 1):
            try:
                response = await self.make_authenticated_request(
                    method, url, scopes=scopes, **kwargs
                )
                
                # If 401, token might be expired - try refreshing
                if response.status_code == 401 and attempt < max_retries:
                    logger.warning("Received 401, refreshing token", attempt=attempt + 1)
                    # Force token refresh
                    self._current_token = None
                    continue
                
                return response
                
            except httpx.RequestError as e:
                if attempt < max_retries:
                    wait_time = 2 ** attempt
                    logger.warning("Request failed, retrying", attempt=attempt + 1, wait_time=wait_time)
                    await asyncio.sleep(wait_time)
                    continue
                raise
        
        raise AuthenticationError(f"Failed after {max_retries} retries")
```

## 🛡️ Protecting Services with JWT

### 1. FastAPI JWT Middleware

```python
# mt5_service/dependencies.py
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
import jwt
from typing import List, Optional
import structlog

logger = structlog.get_logger(__name__)
security = HTTPBearer()

async def get_current_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Validate JWT token and return payload."""
    
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication token provided",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    
    try:
        # Option 1: Local validation (faster)
        if settings.JWT_PUBLIC_KEY:
            payload = validate_token_locally(token)
        else:
            # Option 2: Remote validation (more secure)
            payload = await validate_token_remotely(token)
        
        return payload
        
    except Exception as e:
        logger.warning("Token validation failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

def validate_token_locally(token: str) -> dict:
    """Validate JWT token locally using public key."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_PUBLIC_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
        )
        
        # Additional validation
        token_type = payload.get("type")
        if token_type not in ["access", "service"]:
            raise jwt.InvalidTokenError(f"Invalid token type: {token_type}")
        
        return payload
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

async def validate_token_remotely(token: str) -> dict:
    """Validate JWT token via Permiso auth service."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{settings.PERMISO_AUTH_URL}/api/v1/auth/introspect",
                json={"token": token},
                headers={"Authorization": f"Bearer {token}"}
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=401, detail="Token introspection failed")
            
            result = response.json()
            
            if not result.get("active", False):
                raise HTTPException(status_code=401, detail="Token is not active")
            
            # Convert to payload format
            return {
                "sub": result.get("sub"),
                "client_id": result.get("client_id"),
                "scopes": result.get("scope", "").split(),
                "exp": result.get("exp"),
                "type": result.get("token_type", "access").replace("_token", ""),
                "is_trusted": result.get("is_trusted", False)
            }
            
    except httpx.RequestError as e:
        raise HTTPException(status_code=401, detail=f"Token validation error: {str(e)}")

def require_scopes(required_scopes: List[str]):
    """Dependency factory for scope-based authorization."""
    
    async def check_scopes(token_payload: dict = Depends(get_current_token)) -> dict:
        token_scopes = token_payload.get("scopes", [])
        
        # Parse scopes if string
        if isinstance(token_scopes, str):
            token_scopes = token_scopes.split()
        
        # Check for exact matches
        missing_scopes = set(required_scopes) - set(token_scopes)
        
        # Check for implied scopes (admin scopes imply read/write)
        if missing_scopes:
            implied_scopes = get_implied_scopes(token_scopes)
            missing_scopes = missing_scopes - set(implied_scopes)
        
        if missing_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "insufficient_scope",
                    "error_description": f"Missing scopes: {', '.join(missing_scopes)}",
                    "required_scopes": required_scopes,
                    "missing_scopes": list(missing_scopes)
                }
            )
        
        return token_payload
    
    return check_scopes

def get_implied_scopes(token_scopes: List[str]) -> List[str]:
    """Get scopes implied by token scopes."""
    implied = []
    
    for scope in token_scopes:
        # Admin scopes imply read/write for same resource
        if scope.startswith("admin:"):
            resource = scope.split(":", 1)[1]
            implied.extend([f"read:{resource}", f"write:{resource}"])
        
        # System admin implies everything
        if scope == "admin:system":
            implied.extend([
                "trade:open", "trade:close", "trade:modify", "trade:read",
                "account:read", "account:balance", "market:data"
            ])
    
    return implied
```

### 2. Protected Endpoints

```python
# mt5_service/main.py
from fastapi import FastAPI, Depends, HTTPException
from dependencies import require_scopes, get_current_token
from models import Trade, TradeRequest, Account

app = FastAPI(title="MT5 Trading API")

@app.get("/api/v1/trades", response_model=List[Trade])
async def get_trades(
    token_payload: dict = Depends(require_scopes(["trade:read"]))
):
    """Get trades - requires trade:read scope."""
    client_id = token_payload.get("client_id")
    user_id = token_payload.get("sub")
    
    # Your business logic here
    trades = await get_user_trades(user_id)
    return trades

@app.post("/api/v1/trades", response_model=Trade)
async def open_trade(
    trade_request: TradeRequest,
    token_payload: dict = Depends(require_scopes(["trade:open"]))
):
    """Open trade - requires trade:open scope."""
    client_id = token_payload.get("client_id")
    user_id = token_payload.get("sub")
    
    # Validate and execute trade
    trade = await execute_trade(user_id, trade_request)
    return trade

@app.get("/api/v1/account", response_model=Account)
async def get_account(
    token_payload: dict = Depends(require_scopes(["account:read"]))
):
    """Get account info - requires account:read scope."""
    user_id = token_payload.get("sub")
    
    account = await get_account_info(user_id)
    return account

@app.get("/api/v1/admin/stats")
async def get_admin_stats(
    token_payload: dict = Depends(require_scopes(["admin:system"]))
):
    """Admin endpoint - requires admin:system scope and trusted client."""
    if not token_payload.get("is_trusted", False):
        raise HTTPException(status_code=403, detail="Trusted client required")
    
    stats = await get_system_stats()
    return stats
```

## 💻 Client Implementation

### 1. React/TypeScript Client

```typescript
// frontend/src/services/authService.ts
interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

class AuthService {
  private config: {
    authBaseUrl: string;
    clientId: string;
    clientSecret: string;
  };
  private currentToken: TokenResponse | null = null;
  private tokenExpiresAt: number = 0;

  constructor(config: any) {
    this.config = config;
    this.loadTokenFromStorage();
  }

  async getAccessToken(scopes?: string[]): Promise<string> {
    // Check if current token is valid
    if (this.isTokenValid()) {
      return this.currentToken!.access_token;
    }

    // Request new token
    const scopeString = scopes ? scopes.join(' ') : undefined;
    
    const response = await fetch(`${this.config.authBaseUrl}/api/v1/auth/service-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        ...(scopeString && { scope: scopeString })
      })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Authentication failed: ${error.error_description}`);
    }

    const tokenData: TokenResponse = await response.json();
    
    this.currentToken = tokenData;
    this.tokenExpiresAt = Date.now() + (tokenData.expires_in * 1000);
    this.saveTokenToStorage();

    return tokenData.access_token;
  }

  async makeAuthenticatedRequest<T>(
    url: string,
    options: RequestInit = {},
    requiredScopes?: string[]
  ): Promise<T> {
    const token = await this.getAccessToken(requiredScopes);

    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    // Handle 401 - token might be expired
    if (response.status === 401) {
      this.currentToken = null;
      this.clearTokenFromStorage();
      
      // Retry once with fresh token
      const newToken = await this.getAccessToken(requiredScopes);
      
      const retryResponse = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${newToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (!retryResponse.ok) {
        throw new Error(`API request failed: ${retryResponse.statusText}`);
      }

      return retryResponse.json();
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(`API request failed: ${error.error_description || response.statusText}`);
    }

    return response.json();
  }

  private isTokenValid(): boolean {
    if (!this.currentToken) return false;
    return Date.now() < (this.tokenExpiresAt - 60000); // 60s buffer
  }

  private saveTokenToStorage(): void {
    if (this.currentToken) {
      localStorage.setItem('auth_token', JSON.stringify({
        token: this.currentToken,
        expiresAt: this.tokenExpiresAt
      }));
    }
  }

  private loadTokenFromStorage(): void {
    try {
      const stored = localStorage.getItem('auth_token');
      if (stored) {
        const data = JSON.parse(stored);
        this.currentToken = data.token;
        this.tokenExpiresAt = data.expiresAt;
      }
    } catch (error) {
      this.clearTokenFromStorage();
    }
  }

  private clearTokenFromStorage(): void {
    localStorage.removeItem('auth_token');
  }
}

export const authService = new AuthService({
  authBaseUrl: process.env.REACT_APP_AUTH_URL || 'http://localhost:8000',
  clientId: process.env.REACT_APP_CLIENT_ID || 'trading-dashboard',
  clientSecret: process.env.REACT_APP_CLIENT_SECRET || 'your-client-secret'
});
```

### 2. Trading API Client

```typescript
// frontend/src/services/tradingApiClient.ts
import { authService } from './authService';

interface Trade {
  id: number;
  symbol: string;
  volume: number;
  type: 'buy' | 'sell';
  open_price: number;
  current_price: number;
  profit: number;
  open_time: string;
  status: 'open' | 'closed';
}

interface TradeRequest {
  symbol: string;
  volume: number;
  trade_type: 'buy' | 'sell';
  price?: number;
  stop_loss?: number;
  take_profit?: number;
}

class TradingApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = 'http://localhost:8001') {
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  async getTrades(): Promise<Trade[]> {
    return authService.makeAuthenticatedRequest<Trade[]>(
      `${this.baseUrl}/api/v1/trades`,
      { method: 'GET' },
      ['trade:read']
    );
  }

  async openTrade(tradeRequest: TradeRequest): Promise<Trade> {
    return authService.makeAuthenticatedRequest<Trade>(
      `${this.baseUrl}/api/v1/trades`,
      {
        method: 'POST',
        body: JSON.stringify(tradeRequest)
      },
      ['trade:open']
    );
  }

  async closeTrade(tradeId: number): Promise<{ message: string; trade_id: number }> {
    return authService.makeAuthenticatedRequest(
      `${this.baseUrl}/api/v1/trades/${tradeId}`,
      { method: 'DELETE' },
      ['trade:close']
    );
  }

  async getAccountInfo(): Promise<any> {
    return authService.makeAuthenticatedRequest(
      `${this.baseUrl}/api/v1/account`,
      { method: 'GET' },
      ['account:read']
    );
  }
}

export const tradingApiClient = new TradingApiClient(
  process.env.REACT_APP_MT5_API_URL || 'http://localhost:8001'
);
```

## 🐳 Docker Deployment

### Complete Docker Compose

```yaml
# docker-compose.integration.yml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: trading-postgres
    environment:
      POSTGRES_DB: permiso
      POSTGRES_USER: permiso
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U permiso"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - trading-network

  redis:
    image: redis:7-alpine
    container_name: trading-redis
    command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - trading-network

  permiso-auth:
    build:
      context: ./permiso-auth
      dockerfile: Dockerfile
    container_name: permiso-auth
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - DATABASE_URL=postgresql+asyncpg://permiso:${POSTGRES_PASSWORD}@postgres:5432/permiso
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - ACCESS_TOKEN_EXPIRE_MINUTES=15
      - SERVICE_TOKEN_EXPIRE_MINUTES=60
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - trading-network

  mt5-api:
    build:
      context: ./mt5-service
      dockerfile: Dockerfile
    container_name: mt5-api
    ports:
      - "8001:8001"
    environment:
      - PERMISO_AUTH_URL=http://permiso-auth:8000
      - JWT_ALGORITHM=HS256
      - JWT_ISSUER=permiso-auth
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6