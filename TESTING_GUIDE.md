# Keystone Authentication System - Testing Guide

This guide provides comprehensive instructions for running tests in the Keystone authentication system.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Test Structure](#test-structure)
3. [Environment Setup](#environment-setup)
4. [Running Tests](#running-tests)
5. [Test Categories](#test-categories)
6. [Troubleshooting](#troubleshooting)
7. [Writing New Tests](#writing-new-tests)

## Prerequisites

### Required Software

1. **Python 3.11+**
   ```bash
   python --version  # Should be 3.11 or higher
   ```

2. **Docker and Docker Compose**
   ```bash
   docker --version
   docker-compose --version
   ```

3. **Poetry (recommended) or pip**
   ```bash
   poetry --version
   # OR
   pip --version
   ```

### Required Dependencies

Install all dependencies including test dependencies:

```bash
# Using Poetry (recommended)
poetry install --with dev

# OR using pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Test Structure

The test suite is organized to mirror the application structure:

```
tests/
├── conftest.py                 # Global test configuration and fixtures
├── test_runner.py             # Test runner utilities
├── test_app/                  # Tests organized by app modules
│   ├── __init__.py
│   ├── test_models/           # Tests for app.models
│   │   ├── __init__.py
│   │   ├── test_user.py       # User model tests
│   │   ├── test_role.py       # Role model tests
│   │   ├── test_scope.py      # Scope model tests
│   │   ├── test_service_client.py  # ServiceClient model tests
│   │   └── test_refresh_token.py   # RefreshToken model tests
│   ├── test_core/             # Tests for app.core
│   │   ├── __init__.py
│   │   ├── test_jwt.py        # JWT service tests
│   │   ├── test_password.py   # Password utilities tests
│   │   └── test_security.py   # Security utilities tests
│   ├── test_config/           # Tests for app.config
│   │   ├── __init__.py
│   │   ├── test_settings.py   # Settings tests
│   │   ├── test_database.py   # Database config tests
│   │   └── test_redis.py      # Redis config tests
│   └── test_api/              # Tests for API endpoints
│       ├── __init__.py
│       ├── test_auth.py       # Authentication endpoints
│       ├── test_users.py      # User management endpoints
│       └── test_clients.py    # Service client endpoints
├── integration/               # Integration tests
│   ├── __init__.py
│   ├── test_database.py       # Database integration tests
│   ├── test_redis.py          # Redis integration tests
│   └── test_full_flow.py      # End-to-end workflow tests
└── security/                  # Security-focused tests
    ├── __init__.py
    ├── test_authentication.py # Authentication security tests
    └── test_authorization.py  # Authorization security tests
```

## Environment Setup

### Step 1: Set Environment Variables

Create a `.env.test` file for test-specific configuration:

```bash
# .env.test
ENVIRONMENT=testing
DEBUG=true
DATABASE_URL=postgresql+asyncpg://test:test@localhost:5432/test_keystone
REDIS_URL=redis://localhost:6379/1
JWT_SECRET_KEY=test-secret-key-for-testing-only-never-use-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30
```

### Step 2: Start Test Containers

The test suite uses testcontainers to automatically start PostgreSQL and Redis containers. No manual setup required!

However, if you prefer to use external services:

```bash
# Start PostgreSQL (optional - testcontainers will handle this)
docker run -d --name test-postgres \
  -e POSTGRES_USER=test \
  -e POSTGRES_PASSWORD=test \
  -e POSTGRES_DB=test_keystone \
  -p 5432:5432 \
  postgres:15-alpine

# Start Redis (optional - testcontainers will handle this)
docker run -d --name test-redis \
  -p 6379:6379 \
  redis:7-alpine
```

## Running Tests

### Step 1: Activate Virtual Environment

```bash
# Using Poetry
poetry shell

# OR using venv
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows
```

### Step 2: Run All Tests

```bash
# Run all tests with coverage
pytest --cov=app --cov-report=html --cov-report=term

# Run all tests with verbose output
pytest -v

# Run tests in parallel (faster)
pytest -n auto
```

### Step 3: Run Specific Test Categories

```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run only security tests
pytest -m security

# Run tests for specific modules
pytest tests/test_app/test_models/
pytest tests/test_app/test_core/
pytest tests/test_app/test_config/
```

### Step 4: Run Specific Test Files

```bash
# Run user model tests
pytest tests/test_app/test_models/test_user.py

# Run JWT service tests
pytest tests/unit/test_jwt.py

# Run authentication tests
pytest tests/security/test_authentication.py
```

### Step 5: Run Specific Test Methods

```bash
# Run a specific test method
pytest tests/test_app/test_models/test_user.py::TestUserModel::test_user_creation

# Run tests matching a pattern
pytest -k "test_user"
pytest -k "authentication"
```

## Test Categories

### Unit Tests (`@pytest.mark.unit`)

Test individual components in isolation:

```bash
pytest -m unit
```

**Examples:**
- Model method testing
- Utility function testing
- Service class testing

### Integration Tests (`@pytest.mark.integration`)

Test component interactions:

```bash
pytest -m integration
```

**Examples:**
- Database operations
- Redis operations
- API endpoint testing

### Security Tests (`@pytest.mark.security`)

Test security-related functionality:

```bash
pytest -m security
```

**Examples:**
- Authentication flows
- Authorization checks
- Token validation
- Password security

### Slow Tests (`@pytest.mark.slow`)

Tests that take longer to run:

```bash
# Run all tests except slow ones
pytest -m "not slow"

# Run only slow tests
pytest -m slow
```

## Advanced Test Running

### With Coverage Reports

```bash
# Generate HTML coverage report
pytest --cov=app --cov-report=html
# Open htmlcov/index.html in browser

# Generate terminal coverage report
pytest --cov=app --cov-report=term-missing

# Set minimum coverage threshold
pytest --cov=app --cov-fail-under=80
```

### With Test Output

```bash
# Show print statements
pytest -s

# Show detailed output
pytest -v

# Show test durations
pytest --durations=10

# Show slowest tests
pytest --durations=0
```

### Parallel Testing

```bash
# Run tests in parallel (requires pytest-xdist)
pytest -n auto

# Run with specific number of workers
pytest -n 4
```

### Debugging Tests

```bash
# Drop into debugger on failure
pytest --pdb

# Drop into debugger on first failure
pytest -x --pdb

# Run last failed tests only
pytest --lf

# Run failed tests first
pytest --ff
```

## Troubleshooting

### Common Issues

#### 1. Container Startup Issues

**Problem:** Testcontainers fail to start
```
Error: Could not start container
```

**Solution:**
```bash
# Ensure Docker is running
docker ps

# Clean up old containers
docker container prune

# Check Docker permissions (Linux)
sudo usermod -aG docker $USER
# Then logout and login again
```

#### 2. Database Connection Issues

**Problem:** Cannot connect to test database
```
sqlalchemy.exc.OperationalError: could not connect to server
```

**Solution:**
```bash
# Check if PostgreSQL container is running
docker ps | grep postgres

# Check database URL in test settings
echo $DATABASE_URL

# Restart containers
docker-compose down && docker-compose up -d
```

#### 3. Redis Connection Issues

**Problem:** Cannot connect to Redis
```
redis.exceptions.ConnectionError: Error connecting to Redis
```

**Solution:**
```bash
# Check if Redis container is running
docker ps | grep redis

# Test Redis connection
redis-cli ping

# Check Redis URL
echo $REDIS_URL
```

#### 4. Import Errors

**Problem:** Module import failures
```
ModuleNotFoundError: No module named 'app.main'
```

**Solution:**
```bash
# Ensure you're in the project root directory
pwd

# Test imports manually
python tests/test_import.py

# Install dependencies
poetry install --with dev

# Check Python path
python -c "import sys; print(sys.path)"

# Verify app.main exists
ls app/main.py
```

**Problem:** Missing app.main module (common when running test_runner.py)
```
ImportError while loading conftest 'conftest.py'.
conftest.py:13: in <module>
    from app.main import app
E   ModuleNotFoundError: No module named 'app.main'
```

**Solution:**
The `app/main.py` file should exist with the FastAPI application. This file is required for the test configuration to work properly. If missing, it has been created with the basic FastAPI setup.

**Problem:** General module import failures
```
ModuleNotFoundError: No module named 'app'
```

**Solution:**
```bash
# Ensure you're in the project root directory
pwd

# Install dependencies
poetry install --with dev

# Check Python path
python -c "import sys; print(sys.path)"
```

#### 5. Test Discovery Issues

**Problem:** No tests found
```
collected 0 items
```

**Solution:**
```bash
# Check test file naming (must start with test_ or end with _test.py)
ls tests/

# Run with discovery verbose mode
pytest --collect-only

# Check current directory
pwd  # Should be in project root
```

### Performance Issues

#### Slow Test Execution

```bash
# Profile test execution
pytest --durations=10

# Run tests in parallel
pytest -n auto

# Skip slow tests during development
pytest -m "not slow"
```

#### Memory Issues

```bash
# Run tests with memory profiling
pytest --memray

# Limit test scope
pytest tests/test_app/test_models/test_user.py
```

## Writing New Tests

### Test File Structure

```python
"""Tests for [module_name]."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.core.password import hash_password


class TestUserModel:
    """Test User model functionality."""

    @pytest.mark.unit
    async def test_user_creation(self, db_session: AsyncSession):
        """Test user creation."""
        # Arrange
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password_hash": hash_password("TestPassword123!"),
        }
        
        # Act
        user = User(**user_data)
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        
        # Assert
        assert user.id is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
```

### Test Naming Conventions

- **Test files:** `test_[module_name].py`
- **Test classes:** `TestClassName`
- **Test methods:** `test_method_description`

### Test Markers

```python
@pytest.mark.unit          # Unit test
@pytest.mark.integration   # Integration test
@pytest.mark.security      # Security test
@pytest.mark.slow          # Slow running test
@pytest.mark.asyncio       # Async test (automatically applied)
```

### Using Fixtures

```python
async def test_user_with_role(self, db_session: AsyncSession, test_user: User, test_role: Role):
    """Test user with role assignment."""
    test_user.roles.append(test_role)
    await db_session.commit()
    
    assert test_user.has_role(test_role.name)
```

### Testing Async Code

```python
@pytest.mark.unit
async def test_async_function(self):
    """Test async function."""
    result = await some_async_function()
    assert result is not None
```

### Testing Exceptions

```python
@pytest.mark.unit
def test_invalid_input_raises_exception(self):
    """Test that invalid input raises appropriate exception."""
    with pytest.raises(ValueError, match="Invalid input"):
        some_function(invalid_input)
```

## Continuous Integration

### GitHub Actions Example

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install poetry
        poetry install --with dev
    
    - name: Run tests
      run: |
        poetry run pytest --cov=app --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

## Best Practices

### 1. Test Organization
- Mirror the application structure
- Group related tests in classes
- Use descriptive test names

### 2. Test Data
- Use fixtures for reusable test data
- Clean up after each test
- Use factories for complex objects

### 3. Assertions
- Use specific assertions
- Test one thing per test
- Include helpful error messages

### 4. Performance
- Mark slow tests appropriately
- Use parallel execution for large test suites
- Profile and optimize slow tests

### 5. Maintenance
- Keep tests simple and readable
- Update tests when code changes
- Remove obsolete tests

## Summary

This testing guide provides everything needed to run and maintain tests for the Keystone authentication system. The test suite is designed to be:

- **Comprehensive:** Covers all major functionality
- **Fast:** Uses testcontainers and parallel execution
- **Reliable:** Isolated tests with proper cleanup
- **Maintainable:** Clear structure and documentation

For questions or issues, refer to the troubleshooting section or check the project documentation.