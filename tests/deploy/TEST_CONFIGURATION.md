# Permiso Deployment Test Configuration

## 📦 Test Dependencies

### Core Testing Framework
```txt
# Core testing framework
pytest>=7.4.0
pytest-html>=3.2.0
pytest-json-report>=1.5.0
pytest-xdist>=3.3.0
pytest-timeout>=2.1.0
pytest-mock>=3.11.0

# HTTP client and API testing
requests>=2.31.0
httpx>=0.24.0
aiohttp>=3.8.0

# Performance and load testing
locust>=2.15.0
pytest-benchmark>=4.0.0

# Data validation and manipulation
pydantic>=2.0.0
jsonschema>=4.17.0
faker>=19.0.0

# Database testing
asyncpg>=0.28.0
redis>=4.6.0

# Security testing
cryptography>=41.0.0
jwt>=1.3.1

# Utilities
python-dotenv>=1.0.0
colorama>=0.4.6
tabulate>=0.9.0
```

## 🔧 Environment Configuration

### Required Environment Variables
```bash
# Test Target Configuration
PERMISO_BASE_URL=https://localhost:443
PERMISO_HTTP_URL=http://localhost:80
PERMISO_API_BASE=/api/v1

# Test Credentials - Admin User
TEST_ADMIN_USERNAME=admin
TEST_ADMIN_PASSWORD=AdminPass123!
TEST_ADMIN_EMAIL=admin@permiso.test

# Test Credentials - Regular User
TEST_USER_USERNAME=testuser
TEST_USER_PASSWORD=UserPass123!
TEST_USER_EMAIL=user@permiso.test

# Service Client for Testing
TEST_CLIENT_ID=test-client-001
TEST_CLIENT_SECRET=test-secret-123456789
TEST_LIMITED_CLIENT_ID=limited-client-001
TEST_LIMITED_CLIENT_SECRET=limited-secret-123456789

# Test Configuration
TEST_CONCURRENT_USERS=100
TEST_DURATION_SECONDS=300
TEST_TIMEOUT_SECONDS=30
TEST_RETRY_ATTEMPTS=3
TEST_RETRY_DELAY=1

# Performance Thresholds
PERF_HEALTH_THRESHOLD_MS=100
PERF_AUTH_THRESHOLD_MS=500
PERF_CRUD_THRESHOLD_MS=1000
PERF_ADMIN_THRESHOLD_MS=2000

# Security Test Configuration
RATE_LIMIT_TEST_REQUESTS=10
RATE_LIMIT_TEST_WINDOW=60
SECURITY_SCAN_ENABLED=true

# Database Test Configuration
TEST_DB_POOL_SIZE=5
TEST_DB_TIMEOUT=10

# Logging Configuration
TEST_LOG_LEVEL=INFO
TEST_LOG_FORMAT=json
TEST_REPORT_FORMAT=html
```

### Docker Environment Setup
```bash
# Ensure all containers are running
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Verify container health
docker ps --filter "name=permiso" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Check container logs
docker logs permiso-app-1 --tail 50
docker logs permiso-postgres-prod --tail 20
docker logs permiso-redis-prod --tail 20
docker logs permiso-nginx-prod --tail 20
```

## 🎯 Test Configuration Files

### pytest.ini
```ini
[tool:pytest]
minversion = 7.0
addopts = 
    -v
    --strict-markers
    --strict-config
    --html=reports/test_report.html
    --self-contained-html
    --json-report
    --json-report-file=reports/test_report.json
    --timeout=300
testpaths = tests/deploy
python_files = test_*.py
python_classes = Test*
python_functions = test_*
markers =
    infrastructure: Infrastructure and connectivity tests
    endpoints: API endpoint functionality tests
    auth: Authentication and authorization tests
    security: Security validation tests
    performance: Performance and load tests
    integration: Integration and end-to-end tests
    smoke: Quick smoke tests for basic functionality
    slow: Tests that take longer than 30 seconds
    critical: Critical tests that must pass for deployment
filterwarnings =
    ignore::DeprecationWarning
    ignore::PendingDeprecationWarning
```

### Test Data Configuration
```json
{
  "test_users": {
    "admin": {
      "username": "admin",
      "email": "admin@permiso.test",
      "password": "AdminPass123!",
      "first_name": "Admin",
      "last_name": "User",
      "roles": ["admin", "user"],
      "is_active": true,
      "is_verified": true,
      "is_superuser": true
    },
    "regular_user": {
      "username": "testuser",
      "email": "user@permiso.test",
      "password": "UserPass123!",
      "first_name": "Test",
      "last_name": "User",
      "roles": ["user"],
      "is_active": true,
      "is_verified": true,
      "is_superuser": false
    },
    "inactive_user": {
      "username": "inactive",
      "email": "inactive@permiso.test",
      "password": "InactivePass123!",
      "first_name": "Inactive",
      "last_name": "User",
      "roles": ["user"],
      "is_active": false,
      "is_verified": true,
      "is_superuser": false
    }
  },
  "service_clients": {
    "test_client": {
      "client_id": "test-client-001",
      "client_secret": "test-secret-123456789",
      "name": "Test Client",
      "description": "Client for automated testing",
      "client_type": "confidential",
      "scopes": ["read:users", "write:users", "admin:system"],
      "is_active": true,
      "is_trusted": true,
      "access_token_lifetime": 3600,
      "rate_limit_per_minute": 1000,
      "rate_limit_per_hour": 10000
    },
    "limited_client": {
      "client_id": "limited-client-001",
      "client_secret": "limited-secret-123456789",
      "name": "Limited Test Client",
      "description": "Client with limited permissions",
      "client_type": "confidential",
      "scopes": ["read:users"],
      "is_active": true,
      "is_trusted": false,
      "access_token_lifetime": 1800,
      "rate_limit_per_minute": 100,
      "rate_limit_per_hour": 1000
    }
  },
  "roles": [
    {
      "name": "admin",
      "description": "System administrator with full access",
      "scopes": ["admin:system", "admin:users", "admin:roles", "admin:clients"]
    },
    {
      "name": "moderator",
      "description": "Moderator with user management access",
      "scopes": ["read:users", "write:users", "read:roles"]
    },
    {
      "name": "user",
      "description": "Regular user with basic access",
      "scopes": ["read:profile", "write:profile"]
    }
  ],
  "scopes": [
    {
      "name": "admin:system",
      "description": "System administration access",
      "resource": "system",
      "action": "admin"
    },
    {
      "name": "admin:users",
      "description": "User administration access",
      "resource": "users",
      "action": "admin"
    },
    {
      "name": "read:users",
      "description": "Read user information",
      "resource": "users",
      "action": "read"
    },
    {
      "name": "write:users",
      "description": "Modify user information",
      "resource": "users",
      "action": "write"
    }
  ]
}
```

## 🚀 Test Execution Commands

### Quick Smoke Tests (5 minutes)
```bash
# Run basic infrastructure and health checks
pytest tests/deploy/test_infrastructure.py -m "smoke" -v

# Run basic endpoint availability tests
pytest tests/deploy/test_endpoints.py -m "smoke" -v
```

### Comprehensive Functional Tests (30 minutes)
```bash
# Run all endpoint tests
pytest tests/deploy/test_endpoints.py -v

# Run authentication flow tests
pytest tests/deploy/test_auth_flows.py -v

# Run user management tests
pytest tests/deploy/test_user_management.py -v

# Run role and permission tests
pytest tests/deploy/test_roles_permissions.py -v
```

### Security and Performance Tests (20 minutes)
```bash
# Run security validation tests
pytest tests/deploy/test_security.py -v

# Run performance benchmarks
pytest tests/deploy/test_performance.py -v

# Run load tests (requires locust)
locust -f tests/deploy/locustfile.py --host=https://localhost:443
```

### Complete Test Suite (85 minutes)
```bash
# Run all tests with detailed reporting
pytest tests/deploy/ -v --html=reports/full_report.html --json-report-file=reports/full_report.json

# Run tests in parallel (faster execution)
pytest tests/deploy/ -n auto -v --html=reports/parallel_report.html
```

### Continuous Integration Commands
```bash
# Run critical tests only (for CI/CD pipelines)
pytest tests/deploy/ -m "critical" -v --tb=short

# Run tests with coverage reporting
pytest tests/deploy/ --cov=app --cov-report=html --cov-report=term

# Run tests with performance profiling
pytest tests/deploy/ --benchmark-only --benchmark-json=reports/benchmark.json
```

## 📊 Test Reporting Configuration

### HTML Report Configuration
```python
# pytest-html configuration
pytest_html_report_title = "Permiso Deployment Test Report"
pytest_html_table_sort_col = "Result"
pytest_html_table_sort_order = "desc"
```

### JSON Report Schema
```json
{
  "report": {
    "environment": {
      "permiso_version": "1.0.0",
      "test_environment": "production",
      "test_timestamp": "2024-01-15T10:30:00Z",
      "docker_containers": ["app", "postgres", "redis", "nginx"]
    },
    "summary": {
      "total_tests": 150,
      "passed": 145,
      "failed": 3,
      "skipped": 2,
      "duration": 1800.5,
      "success_rate": 96.7
    },
    "categories": {
      "infrastructure": {"passed": 10, "failed": 0, "duration": 30.2},
      "endpoints": {"passed": 67, "failed": 2, "duration": 450.8},
      "security": {"passed": 25, "failed": 1, "duration": 320.1},
      "performance": {"passed": 20, "failed": 0, "duration": 600.3}
    }
  }
}
```

## 🔍 Debugging and Troubleshooting

### Common Issues and Solutions

#### Container Health Issues
```bash
# Check container status
docker ps -a --filter "name=permiso"

# Restart unhealthy containers
docker-compose -f docker-compose.yml -f docker-compose.prod.yml restart

# Check container logs for errors
docker logs permiso-app-1 --tail 100
```

#### Database Connection Issues
```bash
# Test database connectivity
docker exec permiso-postgres-prod pg_isready -U postgres

# Check database logs
docker logs permiso-postgres-prod --tail 50

# Verify database schema
docker exec permiso-postgres-prod psql -U postgres -d permiso -c "\dt"
```

#### Authentication Issues
```bash
# Verify JWT configuration
curl -k https://localhost:443/health

# Test basic authentication
curl -k -X POST https://localhost:443/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=AdminPass123!"
```

### Test Debugging Options
```bash
# Run tests with verbose output and no capture
pytest tests/deploy/ -v -s

# Run specific test with debugging
pytest tests/deploy/test_auth_flows.py::test_user_login -v -s --pdb

# Run tests with custom log level
pytest tests/deploy/ --log-cli-level=DEBUG

# Run tests with profiling
pytest tests/deploy/ --profile --profile-svg
```

## 📈 Performance Monitoring

### Key Metrics to Track
- **Response Times**: Average, median, 95th percentile
- **Throughput**: Requests per second
- **Error Rates**: By endpoint and error type
- **Resource Utilization**: CPU, memory, database connections
- **Concurrent Users**: Maximum supported load

### Performance Thresholds
```python
PERFORMANCE_THRESHOLDS = {
    "health_endpoint": {"max_response_time": 100, "unit": "ms"},
    "auth_endpoints": {"max_response_time": 500, "unit": "ms"},
    "crud_endpoints": {"max_response_time": 1000, "unit": "ms"},
    "admin_endpoints": {"max_response_time": 2000, "unit": "ms"},
    "concurrent_users": {"max_supported": 100, "unit": "users"},
    "error_rate": {"max_acceptable": 1.0, "unit": "percent"}
}
```

This comprehensive test configuration ensures thorough validation of the Permiso authentication system with proper setup, execution, and monitoring capabilities.