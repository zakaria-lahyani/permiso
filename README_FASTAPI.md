# 🔐 Keystone Authentication System (FastAPI)

A high-performance, dockerized centralized authentication and authorization system built with FastAPI, designed for modern async applications and enterprise-grade security.

## 🎯 Overview

Keystone provides a robust identity and authorization platform that supports:

- **Async Performance**: Built with FastAPI for high-throughput async operations
- **User Authentication**: Username/password with OAuth2 flows
- **Service-to-Service Authentication**: Client credentials flow for internal services
- **Role-Based Access Control (RBAC)**: Flexible role and permission management
- **Scope-Based Authorization**: OAuth2-style scope validation
- **JWT Token Management**: Secure token generation, validation, and revocation
- **Enterprise Security**: Password policies, rate limiting, audit logging

## 🏗️ Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        WEB[Web Application]
        MOBILE[Mobile App]
        SERVICE[Internal Services]
    end
    
    subgraph "Keystone Auth System"
        API[FastAPI Application]
        MIDDLEWARE[Auth Middleware]
        JWT[JWT Service]
        CACHE[Redis Cache]
    end
    
    subgraph "Data Layer"
        DB[(PostgreSQL)]
        REDIS[(Redis)]
    end
    
    WEB --> API
    MOBILE --> API
    SERVICE --> API
    
    API --> MIDDLEWARE
    MIDDLEWARE --> JWT
    API --> CACHE
    API --> DB
    CACHE --> REDIS
```

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Poetry (recommended) or pip

### Running with Docker Compose

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd keystone
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start the services**
   ```bash
   docker-compose up -d
   ```

4. **Run database migrations**
   ```bash
   docker-compose exec keystone-app alembic upgrade head
   ```

5. **Verify the deployment**
   ```bash
   curl http://localhost:8000/health
   ```

### Local Development

1. **Install dependencies**
   ```bash
   # Using Poetry (recommended)
   poetry install
   poetry shell
   
   # Or using pip
   pip install -r requirements.txt
   ```

2. **Start dependencies**
   ```bash
   docker-compose -f docker-compose.dev.yml up -d postgres redis
   ```

3. **Run database migrations**
   ```bash
   alembic upgrade head
   ```

4. **Start the development server**
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

5. **Access the API documentation**
   - Swagger UI: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [FastAPI Architecture](ARCHITECTURE_FASTAPI.md) | System design, components, and async patterns |
| [FastAPI Project Structure](PROJECT_STRUCTURE_FASTAPI.md) | Code organization and technical specifications |
| [API Specification](API_SPECIFICATION.md) | Complete API documentation with examples |
| [Security & Deployment](SECURITY_DEPLOYMENT_GUIDE.md) | Security measures and production deployment |

## 🔑 Core Features

### Authentication Types

| Type | Grant Type | Use Case | Token Lifetime |
|------|------------|----------|----------------|
| User Auth | `password` | Web/Mobile apps | 15 minutes |
| Service Auth | `client_credentials` | Service-to-service | 15 minutes |
| Token Refresh | `refresh_token` | Token renewal | 30 days |

### Performance Features

- **Async/Await**: Full async support for high concurrency
- **Connection Pooling**: Efficient database connection management
- **Redis Caching**: Fast token validation and session management
- **Automatic Documentation**: Interactive API docs with FastAPI

### Security Features

- **Argon2 Password Hashing**: Industry-standard password security
- **JWT with JTI**: Token uniqueness and revocation support
- **Rate Limiting**: Configurable per-endpoint rate limits
- **Input Validation**: Pydantic models for request/response validation
- **CORS Support**: Configurable cross-origin resource sharing

## 🛠️ Technology Stack

### Core Framework
- **FastAPI 0.104+** - Modern, fast web framework
- **Uvicorn** - ASGI server for production
- **Pydantic 2.x** - Data validation and serialization
- **Python 3.11+** - Latest Python features and performance

### Database & ORM
- **SQLAlchemy 2.x** - Async ORM with modern syntax
- **Asyncpg** - High-performance PostgreSQL driver
- **Alembic** - Database migration tool
- **PostgreSQL 15+** - Primary database

### Caching & Security
- **Redis 7+** - Token caching and session storage
- **aioredis** - Async Redis client
- **PyJWT** - JWT token handling
- **Passlib** - Password hashing with Argon2

## 📊 API Endpoints

### Authentication
```http
POST /api/v1/auth/token          # User login
POST /api/v1/auth/refresh        # Refresh access token
POST /api/v1/auth/service-token  # Service authentication
POST /api/v1/auth/revoke         # Revoke tokens
POST /api/v1/auth/introspect     # Token introspection
```

### User Management
```http
POST /api/v1/users/register      # User registration
GET  /api/v1/users/profile       # Get user profile
PUT  /api/v1/users/profile       # Update user profile
POST /api/v1/users/change-password # Change password
```

### Admin Operations
```http
GET    /api/v1/admin/users       # List users
POST   /api/v1/admin/users       # Create user
PUT    /api/v1/admin/users/{id}  # Update user
DELETE /api/v1/admin/users/{id}  # Delete user
GET    /api/v1/admin/clients     # List service clients
POST   /api/v1/admin/clients     # Create service client
```

## 🔐 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | PostgreSQL connection string | - | Yes |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` | Yes |
| `JWT_SECRET_KEY` | JWT signing secret (256-bit) | Auto-generated | Yes |
| `DEBUG` | Enable debug mode | `False` | No |
| `ALLOWED_ORIGINS` | CORS allowed origins | `["http://localhost:3000"]` | No |

### Example .env file
```env
# Database
DATABASE_URL=postgresql+asyncpg://keystone:password@localhost:5432/keystone

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_SECRET_KEY=your-super-secret-jwt-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30

# Security
PASSWORD_MIN_LENGTH=8
RATE_LIMIT_LOGIN=5/minute
RATE_LIMIT_API=100/minute

# CORS
ALLOWED_ORIGINS=["http://localhost:3000","https://yourdomain.com"]

# Application
DEBUG=False
HOST=0.0.0.0
PORT=8000
```

## 🧪 Testing

### Run Tests
```bash
# All tests
pytest

# With coverage
pytest --cov=app --cov-report=html

# Specific test file
pytest tests/test_auth.py

# Integration tests only
pytest tests/integration/

# Async tests
pytest -k "async" -v
```

### Test Coverage
- **Unit Tests**: Service layer, security components, utilities
- **Integration Tests**: API endpoints, database operations, Redis caching
- **Security Tests**: Authentication flows, authorization, token validation
- **Performance Tests**: Load testing with async clients

## 📈 Performance & Monitoring

### Performance Features
```python
# Async database operations
async def get_user_by_email(email: str) -> Optional[User]:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()

# Redis caching
async def cache_token(token_id: str, user_data: dict, expire: int = 3600):
    await redis.set(f"token:{token_id}", json.dumps(user_data), ex=expire)
```

### Health Checks
```bash
# Application health
curl http://localhost:8000/health

# Detailed health with metrics
curl http://localhost:8000/metrics
```

### Custom Metrics
- `http_requests_total` - Total HTTP requests
- `http_request_duration_seconds` - Request duration histogram
- `auth_attempts_total` - Authentication attempts counter
- `tokens_generated_total` - Token generation counter

## 🚀 Deployment

### Production Deployment

1. **Build and deploy with Docker**
   ```bash
   # Build image
   docker build -t keystone-auth .
   
   # Deploy with compose
   docker-compose -f docker-compose.yml up -d
   ```

2. **Run database migrations**
   ```bash
   docker-compose exec keystone-app alembic upgrade head
   ```

3. **Create initial admin user**
   ```bash
   docker-compose exec keystone-app python -m app.scripts.create_admin
   ```

### Scaling Considerations

- **Horizontal Scaling**: Multiple FastAPI instances behind load balancer
- **Database Scaling**: Read replicas with async connection pooling
- **Redis Clustering**: High availability caching with Redis Sentinel
- **CDN Integration**: Static content delivery optimization

## 🔧 Development

### Project Structure
```
app/
├── main.py              # FastAPI application
├── config/              # Configuration settings
├── api/v1/              # API route handlers
├── core/                # Core utilities (JWT, security)
├── services/            # Business logic layer
├── models/              # SQLAlchemy models
├── schemas/             # Pydantic schemas
├── crud/                # Database operations
├── middleware/          # Custom middleware
└── utils/               # Helper functions
```

### Code Quality Tools
```bash
# Format code
black app/ tests/
isort app/ tests/

# Lint code
flake8 app/ tests/

# Type checking
mypy app/

# Pre-commit hooks
pre-commit run --all-files
```

### Database Migrations
```bash
# Create migration
alembic revision --autogenerate -m "Add new table"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Install development dependencies (`poetry install`)
4. Make your changes and add tests
5. Run tests and linting (`pytest && black . && flake8`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Guidelines

- Follow FastAPI best practices and async patterns
- Write comprehensive tests for new features
- Use Pydantic models for all request/response validation
- Follow PEP 8 style guidelines with Black formatting
- Add type hints for all functions and methods
- Update documentation for API changes

## 📝 API Examples

### User Authentication
```python
import httpx

async def authenticate_user():
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/api/v1/auth/token",
            json={
                "username": "user@example.com",
                "password": "SecurePassword123!",
                "grant_type": "password"
            }
        )
        return response.json()
```

### Service Authentication
```python
async def get_service_token():
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/api/v1/auth/service-token",
            json={
                "client_id": "trading-service",
                "client_secret": "super-secret-key",
                "grant_type": "client_credentials",
                "scope": "read:trades write:trades"
            }
        )
        return response.json()
```

### Protected Endpoint Access
```python
async def get_user_profile(access_token: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "http://localhost:8000/api/v1/users/profile",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        return response.json()
```

## 🆘 Troubleshooting

### Common Issues

**Issue**: `ImportError: No module named 'app'`
**Solution**: Ensure PYTHONPATH includes the project root or run from project directory

**Issue**: Database connection errors
**Solution**: Check DATABASE_URL format and ensure PostgreSQL is running

**Issue**: Redis connection timeout
**Solution**: Verify Redis is accessible and REDIS_URL is correct

**Issue**: JWT token validation fails
**Solution**: Ensure JWT_SECRET_KEY is consistent across all instances

### Performance Optimization

- Use connection pooling for database operations
- Implement Redis caching for frequently accessed data
- Use async/await for all I/O operations
- Monitor and optimize database queries
- Configure appropriate rate limits

## 🗺️ Roadmap

### Phase 1 (Current)
- [x] FastAPI async architecture
- [x] JWT token management
- [x] SQLAlchemy async ORM
- [x] Redis caching integration
- [x] Comprehensive testing

### Phase 2 (Planned)
- [ ] Social login integration (OAuth2 providers)
- [ ] Multi-factor authentication (TOTP, SMS)
- [ ] Advanced audit logging with structured logs
- [ ] Admin web interface with React/Vue
- [ ] WebSocket support for real-time notifications

### Phase 3 (Future)
- [ ] OpenID Connect provider capabilities
- [ ] Federated authentication with SAML
- [ ] Advanced analytics dashboard
- [ ] Mobile SDK for iOS/Android
- [ ] Kubernetes deployment manifests

---

**Built with ❤️ using FastAPI for high-performance async authentication**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.