# 📦 Installation Guide

This guide will help you set up the permiso Authentication System for development or production use.

## 🔧 Prerequisites

### Required Software

1. **Python 3.11 or higher**
   ```bash
   python --version  # Should be 3.11+
   ```

2. **Docker and Docker Compose**
   ```bash
   docker --version
   docker-compose --version
   ```

3. **Poetry (Recommended) or pip**
   ```bash
   # Install Poetry
   curl -sSL https://install.python-poetry.org | python3 -
   
   # Or use pip
   pip --version
   ```

### System Requirements

- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Storage**: At least 2GB free space
- **Network**: Internet access for downloading dependencies

## 🚀 Quick Installation

### Option 1: Using Docker Compose (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd permiso
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start all services**
   ```bash
   docker-compose up -d
   ```

4. **Verify installation**
   ```bash
   curl http://localhost:8000/health
   ```

### Option 2: Local Development Setup

1. **Clone and navigate to project**
   ```bash
   git clone <repository-url>
   cd permiso
   ```

2. **Install Python dependencies**
   ```bash
   # Using Poetry (recommended)
   poetry install --with dev
   poetry shell
   
   # Or using pip
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

3. **Start database services**
   ```bash
   docker-compose up -d postgres redis
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env file with your database credentials
   ```

5. **Run database migrations**
   ```bash
   alembic upgrade head
   ```

6. **Start the application**
   ```bash
   # Using Poetry
   poetry run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   
   # Or directly
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

## 🔐 Environment Configuration

### Required Environment Variables

Create a `.env` file in the project root:

```bash
# Application
ENVIRONMENT=development
DEBUG=true
HOST=0.0.0.0
PORT=8000

# Database
DATABASE_URL=postgresql+asyncpg://permiso:password@localhost:5432/permiso
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=0

# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=

# JWT Security
JWT_SECRET_KEY=your-super-secret-jwt-key-change-this-in-production
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30

# Password Policy
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGITS=true
PASSWORD_REQUIRE_SPECIAL=true

# Rate Limiting
RATE_LIMIT_LOGIN=5/minute
RATE_LIMIT_REGISTER=3/hour
RATE_LIMIT_API=100/minute

# CORS
ALLOWED_ORIGINS=["http://localhost:3000","http://localhost:8080"]
ALLOWED_HOSTS=["localhost","127.0.0.1","*"]
```

### Production Environment Variables

For production, ensure you set:

```bash
ENVIRONMENT=production
DEBUG=false
JWT_SECRET_KEY=<generate-strong-256-bit-key>
DATABASE_URL=<production-database-url>
REDIS_URL=<production-redis-url>
ALLOWED_ORIGINS=["https://yourdomain.com"]
ALLOWED_HOSTS=["yourdomain.com"]
```

## 🗄️ Database Setup

### PostgreSQL Setup

#### Using Docker (Recommended)
```bash
docker run -d \
  --name permiso-postgres \
  -e POSTGRES_USER=permiso \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=permiso \
  -p 5432:5432 \
  postgres:15-alpine
```

#### Manual Installation
1. Install PostgreSQL 15+
2. Create database and user:
   ```sql
   CREATE DATABASE permiso;
   CREATE USER permiso WITH PASSWORD 'password';
   GRANT ALL PRIVILEGES ON DATABASE permiso TO permiso;
   ```

### Redis Setup

#### Using Docker (Recommended)
```bash
docker run -d \
  --name permiso-redis \
  -p 6379:6379 \
  redis:7-alpine
```

#### Manual Installation
1. Install Redis 7+
2. Start Redis server:
   ```bash
   redis-server
   ```

## 🧪 Verify Installation

### Health Check
```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "permiso-auth",
  "version": "1.0.0",
  "environment": "development"
}
```

### Run Tests
```bash
# Using Poetry
poetry run pytest

# Or directly
pytest
```

### Check Database Connection
```bash
# Using Poetry
poetry run python -c "from app.config.database import test_connection; import asyncio; asyncio.run(test_connection())"
```

## 🐳 Docker Development

### Development with Docker Compose

1. **Start development environment**
   ```bash
   docker-compose -f docker-compose.dev.yml up -d
   ```

2. **View logs**
   ```bash
   docker-compose logs -f permiso-app
   ```

3. **Execute commands in container**
   ```bash
   docker-compose exec permiso-app bash
   ```

4. **Run tests in container**
   ```bash
   docker-compose exec permiso-app pytest
   ```

## 🔧 Development Tools

### Code Quality Tools

Install and configure development tools:

```bash
# Using Poetry
poetry install --with dev

# Pre-commit hooks
pre-commit install

# Code formatting
black app/ tests/
isort app/ tests/

# Type checking
mypy app/

# Linting
flake8 app/ tests/
```

### IDE Setup

#### VS Code
Install recommended extensions:
- Python
- Pylance
- Python Docstring Generator
- GitLens
- Docker

#### PyCharm
1. Open project in PyCharm
2. Configure Python interpreter to use Poetry environment
3. Enable pytest as test runner

## 🚨 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Find process using port 8000
lsof -i :8000
# Kill the process
kill -9 <PID>
```

#### Database Connection Issues
```bash
# Check if PostgreSQL is running
docker ps | grep postgres
# Check connection
psql -h localhost -U permiso -d permiso
```

#### Permission Issues (Linux/Mac)
```bash
# Fix Docker permissions
sudo usermod -aG docker $USER
# Logout and login again
```

#### Poetry Issues
```bash
# Clear Poetry cache
poetry cache clear --all pypi
# Reinstall dependencies
poetry install --with dev
```

## 📚 Next Steps

After successful installation:

1. [Quick Start Guide](quick-start.md) - Get familiar with basic operations
2. [Configuration Guide](configuration.md) - Detailed configuration options
3. [API Documentation](../api/authentication.md) - Learn about the API endpoints
4. [Testing Guide](../development/testing.md) - Run and write tests

## 🆘 Getting Help

If you encounter issues:

1. Check the [Troubleshooting Guide](../development/troubleshooting.md)
2. Search [existing issues](https://github.com/your-org/permiso/issues)
3. Create a [new issue](https://github.com/your-org/permiso/issues/new) with:
   - Your operating system
   - Python version
   - Error messages
   - Steps to reproduce

---

**Installation complete! 🎉 Ready to build secure authentication systems.**