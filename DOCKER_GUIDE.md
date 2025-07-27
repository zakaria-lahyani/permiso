# Docker Development Guide - permiso Authentication System

This guide provides comprehensive instructions for using Docker containers to develop and test the permiso authentication system.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Container Architecture](#container-architecture)
3. [Development Workflow](#development-workflow)
4. [Testing](#testing)
5. [Troubleshooting](#troubleshooting)
6. [Advanced Usage](#advanced-usage)

## Quick Start

### Prerequisites

- Docker Desktop installed and running
- Docker Compose v2.0+
- Git (for cloning the repository)

### 1. Setup Development Environment

```bash
# Linux/Mac
chmod +x scripts/test.sh
./scripts/test.sh setup

# Windows
scripts\test.bat setup
```

This command will:
- Start PostgreSQL and Redis containers
- Build the development container
- Run database migrations
- Set up the complete development environment

### 2. Run Tests

```bash
# Run all tests
./scripts/test.sh test

# Run specific test types
./scripts/test.sh test unit
./scripts/test.sh test integration
./scripts/test.sh test coverage

# Windows
scripts\test.bat test
scripts\test.bat test unit
```

### 3. Access Development Container

```bash
# Enter the development container
docker-compose exec permiso-dev bash

# Inside the container, you can run:
poetry run pytest
poetry run python tests/test_import.py
poetry run alembic upgrade head
```

## Container Architecture

### Services Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │      Redis      │    │  PostgreSQL     │
│   (Main DB)     │    │    (Cache)      │    │   (Test DB)     │
│   Port: 5432    │    │   Port: 6379    │    │   Port: 5433    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
         │  Redis (Test)   │    │  permiso Dev   │    │ permiso Test   │
         │  Port: 6380     │    │   Container     │    │   Container     │
         └─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Container Details

#### 1. **permiso-dev** (Development Container)
- **Purpose**: Interactive development and testing
- **Features**: 
  - Live code reloading via volume mounts
  - Full development dependencies
  - Interactive shell access
  - Database migration tools

#### 2. **permiso-test** (Test Container)
- **Purpose**: Automated testing and CI/CD
- **Features**:
  - Isolated test environment
  - Automated test execution
  - Coverage reporting
  - JUnit XML output

#### 3. **permiso-app** (Application Container)
- **Purpose**: Production-like testing
- **Features**:
  - FastAPI application server
  - Health checks
  - Production dependencies only
  - Port 8000 exposed

#### 4. **postgres** (Main Database)
- **Purpose**: Primary database for development
- **Features**:
  - PostgreSQL 15 with extensions
  - Persistent data storage
  - Audit logging setup

#### 5. **postgres-test** (Test Database)
- **Purpose**: Isolated database for testing
- **Features**:
  - Separate from main database
  - Clean state for each test run
  - Fast setup and teardown

#### 6. **redis** & **redis-test** (Cache Services)
- **Purpose**: Caching and session storage
- **Features**:
  - Redis 7 with optimized configuration
  - Separate instances for dev and test
  - Persistent storage for development

## Development Workflow

### 1. Initial Setup

```bash
# Clone the repository
git clone <repository-url>
cd permiso

# Start development environment
./scripts/test.sh setup
```

### 2. Daily Development

```bash
# Start services (if not running)
docker-compose up -d

# Enter development container
docker-compose exec permiso-dev bash

# Inside container - run tests
poetry run pytest tests/test_app/test_models/test_user.py -v

# Run specific test with debugging
poetry run pytest tests/test_app/test_models/test_user.py::TestUserModel::test_user_creation -v -s

# Check imports
poetry run python tests/test_import.py

# Run database migrations
poetry run alembic upgrade head

# Generate new migration
poetry run alembic revision --autogenerate -m "Add new feature"
```

### 3. Code Changes

Since the project directory is mounted as a volume (`./:/app`), any changes you make to the code on your host machine are immediately reflected in the container. This enables:

- **Live Development**: Edit files in your IDE, test immediately in container
- **Hot Reloading**: FastAPI automatically reloads on code changes
- **Persistent Changes**: All changes are saved to your host filesystem

### 4. Database Management

```bash
# Connect to main database
docker-compose exec postgres psql -U permiso -d permiso

# Connect to test database
docker-compose exec postgres-test psql -U permiso_test -d permiso_test

# Run migrations
docker-compose exec permiso-dev poetry run alembic upgrade head

# Reset database (careful!)
docker-compose exec permiso-dev poetry run alembic downgrade base
docker-compose exec permiso-dev poetry run alembic upgrade head
```

## Testing

### Test Types

#### 1. Unit Tests
```bash
# Run all unit tests
./scripts/test.sh test unit

# Run specific model tests
./scripts/test.sh file tests/test_app/test_models/test_user.py

# Run with coverage
docker-compose exec permiso-dev poetry run pytest tests/test_app/test_models/ --cov=app.models --cov-report=term
```

#### 2. Integration Tests
```bash
# Run integration tests
./scripts/test.sh test integration

# Run database integration tests
./scripts/test.sh file tests/integration/test_database.py
```

#### 3. Security Tests
```bash
# Run security tests
./scripts/test.sh test security

# Run authentication tests
./scripts/test.sh file tests/security/test_authentication.py
```

#### 4. Import Tests
```bash
# Test all imports
./scripts/test.sh imports

# Manual import testing
docker-compose exec permiso-dev poetry run python -c "from app.main import app; print('Success!')"
```

### Test Reports

Test reports are automatically generated and stored in volumes:

- **Coverage Reports**: `htmlcov/index.html` (accessible via volume mount)
- **JUnit XML**: `test-reports/junit.xml`
- **Coverage XML**: `coverage.xml`

```bash
# View coverage report (after running tests with coverage)
open htmlcov/index.html  # Mac
start htmlcov/index.html # Windows
```

### Continuous Testing

```bash
# Run tests in dedicated container (CI-style)
./scripts/test.sh test-container

# This will:
# 1. Build fresh test container
# 2. Run complete test suite
# 3. Generate all reports
# 4. Exit with proper status code
```

## Troubleshooting

### Common Issues

#### 1. Container Won't Start

```bash
# Check Docker status
docker info

# Check container logs
./scripts/test.sh logs permiso-dev

# Rebuild containers
docker-compose build --no-cache permiso-dev
```

#### 2. Database Connection Issues

```bash
# Check database status
docker-compose ps postgres

# Check database logs
./scripts/test.sh logs postgres

# Reset database
docker-compose down postgres
docker volume rm permiso_postgres_data
docker-compose up -d postgres
```

#### 3. Import Errors

```bash
# Test imports specifically
./scripts/test.sh imports

# Check Python path
docker-compose exec permiso-dev poetry run python -c "import sys; print(sys.path)"

# Reinstall dependencies
docker-compose exec permiso-dev poetry install --with dev
```

#### 4. Port Conflicts

If you get port conflicts, modify `docker-compose.yml`:

```yaml
services:
  postgres:
    ports:
      - "5434:5432"  # Change from 5432 to 5434
  redis:
    ports:
      - "6380:6379"  # Change from 6379 to 6380
```

#### 5. Permission Issues (Linux/Mac)

```bash
# Fix file permissions
sudo chown -R $USER:$USER .
chmod +x scripts/test.sh

# Or run with sudo if needed
sudo ./scripts/test.sh setup
```

### Debugging

#### 1. Interactive Debugging

```bash
# Enter container with bash
docker-compose exec permiso-dev bash

# Run Python interactively
docker-compose exec permiso-dev poetry run python

# Debug specific test
docker-compose exec permiso-dev poetry run pytest tests/test_app/test_models/test_user.py::TestUserModel::test_user_creation -v -s --pdb
```

#### 2. Log Analysis

```bash
# View all logs
./scripts/test.sh logs

# View specific service logs
./scripts/test.sh logs postgres
./scripts/test.sh logs permiso-dev

# Follow logs in real-time
docker-compose logs -f permiso-dev
```

#### 3. Container Inspection

```bash
# Inspect container
docker inspect permiso-dev

# Check container resources
docker stats permiso-dev

# List container processes
docker-compose exec permiso-dev ps aux
```

## Advanced Usage

### 1. Custom Environment Variables

Create a `.env.local` file:

```bash
# .env.local
DATABASE_URL=postgresql+asyncpg://custom_user:custom_pass@postgres:5432/custom_db
REDIS_URL=redis://redis:6379/2
JWT_SECRET_KEY=my-custom-secret-key
DEBUG=true
```

Then use it:

```bash
docker-compose --env-file .env.local up -d
```

### 2. Production-like Testing

```bash
# Start application container
docker-compose --profile app up -d permiso-app

# Test the API
curl http://localhost:8000/health
curl http://localhost:8000/docs
```

### 3. Performance Testing

```bash
# Run performance tests
docker-compose exec permiso-dev poetry run pytest tests/ -m "not slow" --durations=10

# Memory profiling
docker-compose exec permiso-dev poetry run pytest --memray tests/test_app/test_models/
```

### 4. Database Seeding

```bash
# Create seed data script
docker-compose exec permiso-dev poetry run python scripts/seed_data.py

# Or run SQL directly
docker-compose exec postgres psql -U permiso -d permiso -f scripts/seed.sql
```

### 5. Backup and Restore

```bash
# Backup database
docker-compose exec postgres pg_dump -U permiso permiso > backup.sql

# Restore database
docker-compose exec -T postgres psql -U permiso permiso < backup.sql
```

## Cleanup

### Regular Cleanup

```bash
# Stop and remove containers
./scripts/test.sh cleanup

# Or manually
docker-compose down -v
docker system prune -f
```

### Complete Reset

```bash
# Remove everything (careful!)
docker-compose down -v --rmi all
docker system prune -a -f --volumes

# Then setup again
./scripts/test.sh setup
```

## Best Practices

### 1. Development
- Always use the development container for testing
- Keep the host filesystem clean by working inside containers
- Use volume mounts for live code reloading
- Commit frequently to avoid losing work

### 2. Testing
- Run tests in isolated containers
- Use separate databases for testing
- Generate coverage reports regularly
- Test imports before running full test suite

### 3. Debugging
- Use container logs for troubleshooting
- Test individual components before integration
- Keep containers running for faster iteration
- Use interactive debugging when needed

### 4. Performance
- Use Docker BuildKit for faster builds
- Cache dependencies with volume mounts
- Run tests in parallel when possible
- Monitor container resource usage

This Docker setup provides a complete, isolated, and reproducible development environment for the permiso authentication system, making it easy to develop, test, and debug without affecting your host system.