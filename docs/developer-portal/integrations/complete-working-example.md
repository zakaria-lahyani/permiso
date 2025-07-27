# 🚀 Complete Working Example: Trading System Integration

This document provides a complete, working example of integrating Permiso Auth into a trading system with a React dashboard, MT5 API service, and comprehensive Docker deployment.

## 📁 Project Structure

```
trading-system/
├── permiso-auth/                 # Permiso authentication service
│   ├── app/                     # (existing Permiso codebase)
│   ├── Dockerfile
│   └── requirements.txt
├── mt5-service/                 # MT5 API service
│   ├── main.py
│   ├── dependencies.py
│   ├── models.py
│   ├── mt5_client.py
│   ├── config.py
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/                    # React trading dashboard
│   ├── src/
│   │   ├── services/
│   │   │   ├── authService.ts
│   │   │   └── tradingApiClient.ts
│   │   ├── components/
│   │   │   └── TradingDashboard.tsx
│   │   └── App.tsx
│   ├── package.json
│   └── Dockerfile
├── nginx/
│   └── nginx.conf
├── scripts/
│   ├── setup-services.py
│   └── test-integration.py
├── docker-compose.yml
├── .env.example
└── README.md
```

## 🔧 Complete Implementation

### 1. MT5 Service Implementation

```python
# mt5-service/main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
import structlog
from typing import List

from dependencies import get_current_token, require_scopes, get_mt5_connection
from models import Trade, TradeRequest, Account, MarketData
from config import settings

logger = structlog.get_logger(__name__)

app = FastAPI(
    title="MT5 Trading API",
    description="MetaTrader 5 integration with Permiso authentication",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "mt5-api", "version": "1.0.0"}

@app.get("/api/v1/trades", response_model=List[Trade])
async def get_trades(
    token_payload: dict = Depends(require_scopes(["trade:read"])),
    mt5_conn = Depends(get_mt5_connection)
):
    """Get all trades for the authenticated client."""
    try:
        client_id = token_payload.get("client_id")
        user_id = token_payload.get("sub")
        
        logger.info("Fetching trades", client_id=client_id, user_id=user_id)
        
        trades = await mt5_conn.get_trades(user_id=user_id)
        return [Trade.from_mt5_trade(trade) for trade in trades]
        
    except Exception as e:
        logger.error("Failed to fetch trades", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to fetch trades")

@app.post("/api/v1/trades", response_model=Trade)
async def open_trade(
    trade_request: TradeRequest,
    token_payload: dict = Depends(require_scopes(["trade:open"])),
    mt5_conn = Depends(get_mt5_connection)
):
    """Open a new trade."""
    try:
        client_id = token_payload.get("client_id")
        user_id = token_payload.get("sub")
        
        logger.info(
            "Opening trade",
            client_id=client_id,
            user_id=user_id,
            symbol=trade_request.symbol,
            volume=trade_request.volume
        )
        
        trade_result = await mt5_conn.open_trade(
            user_id=user_id,
            symbol=trade_request.symbol,
            volume=trade_request.volume,
            trade_type=trade_request.trade_type,
            price=trade_request.price,
            stop_loss=trade_request.stop_loss,
            take_profit=trade_request.take_profit
        )
        
        if not trade_result.success:
            raise HTTPException(status_code=400, detail=f"Trade failed: {trade_result.error}")
        
        return Trade.from_mt5_trade(trade_result.trade)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to open trade", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to open trade")

@app.delete("/api/v1/trades/{trade_id}")
async def close_trade(
    trade_id: int,
    token_payload: dict = Depends(require_scopes(["trade:close"])),
    mt5_conn = Depends(get_mt5_connection)
):
    """Close an existing trade."""
    try:
        client_id = token_payload.get("client_id")
        user_id = token_payload.get("sub")
        
        logger.info("Closing trade", client_id=client_id, user_id=user_id, trade_id=trade_id)
        
        close_result = await mt5_conn.close_trade(user_id=user_id, trade_id=trade_id)
        
        if not close_result.success:
            raise HTTPException(status_code=400, detail=f"Close failed: {close_result.error}")
        
        return {"message": "Trade closed successfully", "trade_id": trade_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to close trade", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to close trade")

@app.get("/api/v1/account", response_model=Account)
async def get_account_info(
    token_payload: dict = Depends(require_scopes(["account:read"])),
    mt5_conn = Depends(get_mt5_connection)
):
    """Get account information."""
    try:
        user_id = token_payload.get("sub")
        account_info = await mt5_conn.get_account_info(user_id=user_id)
        return Account.from_mt5_account(account_info)
        
    except Exception as e:
        logger.error("Failed to fetch account info", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to fetch account information")

@app.get("/api/v1/market/{symbol}", response_model=MarketData)
async def get_market_data(
    symbol: str,
    token_payload: dict = Depends(require_scopes(["market:data"])),
    mt5_conn = Depends(get_mt5_connection)
):
    """Get market data for a symbol."""
    try:
        market_data = await mt5_conn.get_market_data(symbol=symbol)
        return MarketData.from_mt5_data(market_data)
        
    except Exception as e:
        logger.error("Failed to fetch market data", error=str(e), symbol=symbol)
        raise HTTPException(status_code=500, detail=f"Failed to fetch market data for {symbol}")
```

### 2. Models and Data Structures

```python
# mt5-service/models.py
from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime
from decimal import Decimal

class TradeRequest(BaseModel):
    symbol: str = Field(..., min_length=1, max_length=20)
    volume: float = Field(..., gt=0, le=100)
    trade_type: Literal["buy", "sell"]
    price: Optional[float] = None
    stop_loss: Optional[float] = None
    take_profit: Optional[float] = None

class Trade(BaseModel):
    id: int
    symbol: str
    volume: float
    type: Literal["buy", "sell"]
    open_price: float
    current_price: float
    profit: float
    open_time: datetime
    status: Literal["open", "closed"]
    
    @classmethod
    def from_mt5_trade(cls, mt5_trade):
        """Convert MT5 trade object to Trade model."""
        return cls(
            id=mt5_trade.ticket,
            symbol=mt5_trade.symbol,
            volume=mt5_trade.volume,
            type="buy" if mt5_trade.type == 0 else "sell",
            open_price=mt5_trade.price_open,
            current_price=mt5_trade.price_current,
            profit=mt5_trade.profit,
            open_time=datetime.fromtimestamp(mt5_trade.time),
            status="open" if mt5_trade.state == 1 else "closed"
        )

class Account(BaseModel):
    balance: float
    equity: float
    margin: float
    free_margin: float
    margin_level: float
    currency: str
    
    @classmethod
    def from_mt5_account(cls, mt5_account):
        """Convert MT5 account info to Account model."""
        return cls(
            balance=mt5_account.balance,
            equity=mt5_account.equity,
            margin=mt5_account.margin,
            free_margin=mt5_account.margin_free,
            margin_level=mt5_account.margin_level,
            currency=mt5_account.currency
        )

class MarketData(BaseModel):
    symbol: str
    bid: float
    ask: float
    spread: float
    last_update: datetime
    
    @classmethod
    def from_mt5_data(cls, mt5_data):
        """Convert MT5 market data to MarketData model."""
        return cls(
            symbol=mt5_data.symbol,
            bid=mt5_data.bid,
            ask=mt5_data.ask,
            spread=mt5_data.ask - mt5_data.bid,
            last_update=datetime.fromtimestamp(mt5_data.time)
        )
```

### 3. MT5 Client Implementation

```python
# mt5-service/mt5_client.py
import MetaTrader5 as mt5
import asyncio
from typing import List, Optional
from dataclasses import dataclass
import structlog

logger = structlog.get_logger(__name__)

@dataclass
class TradeResult:
    success: bool
    trade: Optional[object] = None
    error: Optional[str] = None

@dataclass
class CloseResult:
    success: bool
    error: Optional[str] = None

class MT5Client:
    """MetaTrader 5 client wrapper."""
    
    def __init__(self):
        self.initialized = False
    
    async def initialize(self):
        """Initialize MT5 connection."""
        if not self.initialized:
            if not mt5.initialize():
                error = mt5.last_error()
                logger.error("MT5 initialization failed", error=error)
                raise Exception(f"MT5 initialization failed: {error}")
            
            self.initialized = True
            logger.info("MT5 initialized successfully")
    
    async def get_trades(self, user_id: str) -> List:
        """Get all open trades for a user."""
        await self.initialize()
        
        try:
            # In a real implementation, you'd filter by user account
            positions = mt5.positions_get()
            if positions is None:
                logger.warning("No positions found")
                return []
            
            return list(positions)
            
        except Exception as e:
            logger.error("Failed to get trades", error=str(e))
            raise
    
    async def open_trade(
        self,
        user_id: str,
        symbol: str,
        volume: float,
        trade_type: str,
        price: Optional[float] = None,
        stop_loss: Optional[float] = None,
        take_profit: Optional[float] = None
    ) -> TradeResult:
        """Open a new trade."""
        await self.initialize()
        
        try:
            # Prepare trade request
            request = {
                "action": mt5.TRADE_ACTION_DEAL,
                "symbol": symbol,
                "volume": volume,
                "type": mt5.ORDER_TYPE_BUY if trade_type == "buy" else mt5.ORDER_TYPE_SELL,
                "deviation": 20,
                "magic": 234000,
                "comment": f"Permiso trade for {user_id}",
                "type_time": mt5.ORDER_TIME_GTC,
                "type_filling": mt5.ORDER_FILLING_IOC,
            }
            
            if price:
                request["price"] = price
            
            if stop_loss:
                request["sl"] = stop_loss
            
            if take_profit:
                request["tp"] = take_profit
            
            # Send trade request
            result = mt5.order_send(request)
            
            if result.retcode != mt5.TRADE_RETCODE_DONE:
                error_msg = f"Trade failed: {result.retcode} - {result.comment}"
                logger.error("Trade execution failed", error=error_msg, request=request)
                return TradeResult(success=False, error=error_msg)
            
            logger.info("Trade opened successfully", order=result.order, deal=result.deal)
            
            # Get the opened position
            position = mt5.positions_get(ticket=result.order)
            if position:
                return TradeResult(success=True, trade=position[0])
            else:
                return TradeResult(success=False, error="Position not found after opening")
            
        except Exception as e:
            logger.error("Failed to open trade", error=str(e))
            return TradeResult(success=False, error=str(e))
    
    async def close_trade(self, user_id: str, trade_id: int) -> CloseResult:
        """Close an existing trade."""
        await self.initialize()
        
        try:
            # Get position info
            position = mt5.positions_get(ticket=trade_id)
            if not position:
                return CloseResult(success=False, error="Position not found")
            
            position = position[0]
            
            # Prepare close request
            request = {
                "action": mt5.TRADE_ACTION_DEAL,
                "symbol": position.symbol,
                "volume": position.volume,
                "type": mt5.ORDER_TYPE_SELL if position.type == 0 else mt5.ORDER_TYPE_BUY,
                "position": trade_id,
                "deviation": 20,
                "magic": 234000,
                "comment": f"Close trade for {user_id}",
                "type_time": mt5.ORDER_TIME_GTC,
                "type_filling": mt5.ORDER_FILLING_IOC,
            }
            
            # Send close request
            result = mt5.order_send(request)
            
            if result.retcode != mt5.TRADE_RETCODE_DONE:
                error_msg = f"Close failed: {result.retcode} - {result.comment}"
                logger.error("Trade close failed", error=error_msg, request=request)
                return CloseResult(success=False, error=error_msg)
            
            logger.info("Trade closed successfully", deal=result.deal)
            return CloseResult(success=True)
            
        except Exception as e:
            logger.error("Failed to close trade", error=str(e))
            return CloseResult(success=False, error=str(e))
    
    async def get_account_info(self, user_id: str):
        """Get account information."""
        await self.initialize()
        
        try:
            account_info = mt5.account_info()
            if account_info is None:
                raise Exception("Failed to get account info")
            
            return account_info
            
        except Exception as e:
            logger.error("Failed to get account info", error=str(e))
            raise
    
    async def get_market_data(self, symbol: str):
        """Get market data for a symbol."""
        await self.initialize()
        
        try:
            tick = mt5.symbol_info_tick(symbol)
            if tick is None:
                raise Exception(f"Failed to get market data for {symbol}")
            
            return tick
            
        except Exception as e:
            logger.error("Failed to get market data", error=str(e), symbol=symbol)
            raise
    
    def __del__(self):
        """Cleanup MT5 connection."""
        if self.initialized:
            mt5.shutdown()
```

### 4. Complete Docker Compose Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  # PostgreSQL Database
  postgres:
    image: postgres:15-alpine
    container_name: trading-postgres
    environment:
      POSTGRES_DB: permiso
      POSTGRES_USER: permiso
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init-db.sql:ro
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U permiso"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - trading-network
    restart: unless-stopped

  # Redis Cache
  redis:
    image: redis:7-alpine
    container_name: trading-redis
    command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - trading-network
    restart: unless-stopped

  # Permiso Authentication Service
  permiso-auth:
    build:
      context: ./permiso-auth
      dockerfile: Dockerfile
      target: production
    container_name: permiso-auth
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - DATABASE_URL=postgresql+asyncpg://permiso:${POSTGRES_PASSWORD}@postgres:5432/permiso
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - JWT_ALGORITHM=HS256
      - JWT_ISSUER=permiso-auth
      - ACCESS_TOKEN_EXPIRE_MINUTES=15
      - SERVICE_TOKEN_EXPIRE_MINUTES=60
      - ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
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
      start_period: 40s
    networks:
      - trading-network
    restart: unless-stopped

  # MT5 API Service
  mt5-api:
    build:
      context: ./mt5-service
      dockerfile: Dockerfile
    container_name: mt5-api
    ports:
      - "8001:8001"
    environment:
      - SERVICE_NAME=mt5-api-service
      - PERMISO_AUTH_URL=http://permiso-auth:8000
      - JWT_ALGORITHM=HS256
      - JWT_ISSUER=permiso-auth
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/1
      - MT5_SERVER=${MT5_SERVER}
      - MT5_LOGIN=${MT5_LOGIN}
      - MT5_PASSWORD=${MT5_PASSWORD}
      - ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
      - LOG_LEVEL=INFO
    depends_on:
      permiso-auth:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8001/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - trading-network
    restart: unless-stopped

  # Trading Dashboard Frontend
  trading-dashboard:
    build:
      context: ./frontend
      dockerfile: Dockerfile
      target: production
    container_name: trading-dashboard
    ports:
      - "3000:80"
    environment:
      - REACT_APP_AUTH_URL=http://localhost:8000
      - REACT_APP_MT5_API_URL=http://localhost:8001
      - REACT_APP_CLIENT_ID=trading-dashboard
      - REACT_APP_CLIENT_SECRET=${DASHBOARD_CLIENT_SECRET}
    depends_on:
      - permiso-auth
      - mt5-api
    networks:
      - trading-network
    restart: unless-stopped

  # Nginx Reverse Proxy
  nginx:
    image: nginx:alpine
    container_name: trading-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./logs/nginx:/var/log/nginx
    depends_on:
      - permiso-auth
      - mt5-api
      - trading-dashboard
    networks:
      - trading-network
    restart: unless-stopped

volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local

networks:
  trading-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### 5. Setup and Initialization Scripts

```python
# scripts/setup-services.py
import asyncio
import httpx
import json
from typing import Dict, Any
import time

class TradingSystemSetup:
    """Setup script for the complete trading system."""
    
    def __init__(self):
        self.auth_url = "http://localhost:8000"
        self.mt5_api_url = "http://localhost:8001"
        self.admin_credentials = {
            "username": "admin",
            "password": "admin123"  # Change in production
        }
    
    async def setup_complete_system(self):
        """Setup the complete trading system."""
        print("🚀 Setting up Trading System with Permiso Auth...")
        
        # Wait for services to be ready
        await self.wait_for_services()
        
        # Get admin token
        admin_token = await self.get_admin_token()
        
        # Create service clients
        mt5_client = await self.create_mt5_service_client(admin_token)
        dashboard_client = await self.create_dashboard_client(admin_token)
        
        # Create test user
        test_user = await self.create_test_user(admin_token)
        
        # Test the complete flow
        await self.test_complete_flow(mt5_client, dashboard_client)
        
        print("✅ Trading system setup completed successfully!")
        
        # Print summary
        self.print_setup_summary(mt5_client, dashboard_client, test_user)
    
    async def wait_for_services(self):
        """Wait for all services to be ready."""
        services = [
            ("Permiso Auth", f"{self.auth_url}/health"),
            ("MT5 API", f"{self.mt5_api_url}/health")
        ]
        
        for service_name, health_url in services:
            print(f"⏳ Waiting for {service_name}...")
            
            for attempt in range(30):  # 30 attempts, 2 seconds each = 1 minute
                try:
                    async with httpx.AsyncClient(timeout=5.0) as client:
                        response = await client.get(health_url)
                        if response.status_code == 200:
                            print(f"✅ {service_name} is ready")
                            break
                except Exception:
                    pass
                
                if attempt == 29:
                    raise Exception(f"{service_name} did not become ready")
                
                await asyncio.sleep(2)
    
    async def get_admin_token(self) -> str:
        """Get admin authentication token."""
        print("🔑 Getting admin token...")
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.auth_url}/api/v1/auth/token",
                data={
                    "username": self.admin_credentials["username"],
                    "password": self.admin_credentials["password"]
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get admin token: {response.text}")
            
            token_data = response.json()
            return token_data["access_token"]
    
    async def create_mt5_service_client(self, admin_token: str) -> Dict[str, str]:
        """Create MT5 service client."""
        print("🏭 Creating MT5 service client...")
        
        client_config = {
            "client_id": "mt5-api-service",
            "name": "MT5 Trading API Service",
            "description": "MetaTrader 5 integration service for trading operations",
            "client_type": "confidential",
            "is_trusted": True,
            "access_token_lifetime": 3600,
            "rate_limit_per_minute": 300,
            "scope_ids": [
                "trade:open", "trade:close", "trade:modify", "trade:read",
                "account:read", "account:balance", "market:data", "service:mt5"
            ]
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.auth_url}/api/v1/admin/service-clients",
                headers={"Authorization": f"Bearer {admin_token}"},
                json=client_config
            )
            
            if response.status_code == 201:
                client_data = response.json()
                print("✅ MT5 service client created successfully")
                return {
                    "client_id": client_data["client"]["client_id"],
                    "client_secret": client_data["client_secret"]
                }
            elif response.status_code == 409:
                print("ℹ️ MT5 service client already exists")
                return {"client_id": "mt5-api-service", "client_secret": "existing"}
            else:
                raise Exception(f"Failed to create MT5 client: {response.text}")
    
    async def create_dashboard_client(self, admin_token: str) -> Dict[str, str]:
        """Create dashboard client."""
        print("🖥️ Creating dashboard client...")
        
        client_config = {
            "client_id": "trading-dashboard",
            "name": "Trading Dashboard Web App",
            "description": "Web-based trading dashboard for retail clients",
            "client_type": "confidential",
            "is_trusted": False,
            "access_token_lifetime": 1800,
            "rate_limit_per_minute": 120,
            "scope_ids": [
                "read:profile", "write:profile", "trade:read", 
                "trade:open", "account:read", "market:data"
            ]
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.auth_url}/api/v1/admin/service-clients",
                headers={"Authorization": f"Bearer {admin_token}"},
                json=client_config
            )
            
            if response.status_code == 201:
                client_data = response.json()
                print("✅ Dashboard client created successfully")
                return {
                    "client_id": client_data["client"]["client_id"],
                    "client_secret": client_data["client_secret"]
                }
            elif response.status_code == 409:
                print("ℹ️ Dashboard client already exists")
                return {"client_id": "trading-dashboard", "client_secret": "existing"}
            else:
                raise Exception(f"Failed to create dashboard client: {response.text}")
    
    async def create_test_user(self, admin_token: str) -> Dict[str, str]:
        """Create test user."""
        print("👤 Creating test user...")
        
        user_config = {
            "username": "testtrader",
            "email": "testtrader@example.com",
            "password": "TestTrader123!",
            "first_name": "Test",
            "last_name": "Trader"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.auth_url}/api/v1/users/register",
                json=user_config
            )
            
            if response.status_code == 201:
                print("✅ Test user created successfully")
                return user_config
            elif response.status_code == 409:
                print("ℹ️ Test user already exists")
                return user_config
            else:
                raise Exception(f"Failed to create test user: {response.text}")
    
    async def test_complete_flow(self, mt5_client: Dict[str, str], dashboard_client: Dict[str, str]):
        """Test the complete authentication and API flow."""
        print("🧪 Testing complete integration flow...")
        
        # Test MT5 service token
        async with httpx.AsyncClient() as client:
            # Get MT5 service token
            response = await client.post(
                f"{self.auth_url}/api/v1/auth/service-token",
                data={
                    "client_id": mt5_client["client_id"],
                    "client_secret": mt5_client["client_secret"],
                    "scope": "trade:read account:read"
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"MT5 token request failed: {response.text}")
            
            mt5_token = response.json()["access_token"]
            
            # Test MT5 API access
            response = await client.get(
                f"{self.mt5_api_url}/api/v1/trades",
                headers={"Authorization": f"Bearer {mt5_token}"}
            )
            
            if response.status_code == 200:
                print("✅ MT5 API access test successful")
            else:
                print(f"⚠️ MT5 API access test failed: {response.status_code}")
        
        print("✅ Integration flow test completed")
    
    def print_setup_summary(self, mt5_client: Dict[str, str], dashboard_client: Dict[str, str], test_user: Dict[str, str]):
        """Print setup summary."""
        print("\n" + "="*60)
        print("🎉 TRADING SYSTEM SETUP COMPLETE")
        print("="*60)
        
        print("\n📋 Service Information:")
        print(f"• Permiso Auth: {self.auth_url}")
        print(f"• MT5 API: {self.mt5_api_url}")
        print(f"• Trading Dashboard: http://localhost:3000")
        
        print("\n🔑 Service Clients:")
        print(