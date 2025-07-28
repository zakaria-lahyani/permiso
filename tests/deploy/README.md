# Permiso Deployment Test Suite

## 📋 Overview

This comprehensive test suite validates the complete Permiso authentication system deployment, ensuring all components are healthy, all endpoints are functional, and the system meets security and performance requirements.

## 🏗️ Test Architecture

### Test Categories

1. **Infrastructure Tests** - Container health, database connectivity, Redis functionality
2. **Endpoint Tests** - All 67+ documented API endpoints with various scenarios
3. **Authentication Tests** - Complete OAuth2 flows, JWT lifecycle, service tokens
4. **Security Tests** - Rate limiting, authorization, input validation
5. **Performance Tests** - Load testing, response times, concurrent users
6. **Integration Tests** - Multi-service workflows, complex scenarios

### Test Environment Requirements

- Docker containers running: `permiso-app-1`, `permiso-postgres-prod`, `permiso-redis-prod`, `permiso-nginx-prod`
- Network connectivity to all services
- Valid test credentials and service client configurations
- Sufficient system resources for load testing

## 🔧 Infrastructure Validation

### Container Health Checks
```bash
# Validate all containers are running and healthy
docker logs permiso-redis-prod
docker logs permiso-postgres-prod  
docker logs permiso-nginx-prod --tail 20
docker logs permiso-app-1
```

### Service Connectivity
- **Database**: PostgreSQL connection, schema validation, query execution
- **Redis**: Connection, caching operations, session storage
- **Nginx**: Load balancing, SSL termination, request routing
- **Application**: Health endpoint, metrics endpoint (if enabled)

## 🔐 Authentication & Security Tests

### OAuth2 Flow Validation
1. **User Authentication Flow**
   - Username/password login → Access token + Refresh token
   - Token refresh → New access token + New refresh token
   - Token validation and introspection
   - Logout → Token revocation

2. **Service Client Flow**
   - Client credentials → Service access token
   - Scope validation and enforcement
   - Token lifecycle management

### Security Enforcement
- Rate limiting per endpoint
- JWT signature validation
- Scope-based authorization
- Input sanitization and validation
- CORS policy enforcement

## 📊 Endpoint Test Matrix

### Health & Monitoring (2 endpoints)
- `GET /health` - System health status
- `GET /metrics` - Prometheus metrics (if enabled)

### Authentication (`/api/v1/auth`) - 8 endpoints
- `POST /api/v1/auth/token` - User login
- `POST /api/v1/auth/service-token` - Service client authentication
- `POST /api/v1/auth/refresh` - Token refresh
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/introspect` - Token introspection
- `POST /api/v1/auth/revoke` - Token revocation

### User Management (`/api/v1/users`) - 12 endpoints
- `POST /api/v1/users/register` - User registration
- `GET /api/v1/users/me` - Current user profile
- `GET /api/v1/users/profile` - User profile (alias)
- `PUT /api/v1/users/me` - Update current user profile
- `GET /api/v1/users/{user_id}` - Get user by ID
- `PUT /api/v1/users/{user_id}` - Update user
- `DELETE /api/v1/users/{user_id}` - Delete user
- `PUT /api/v1/users/{user_id}/password` - Update password
- `PUT /api/v1/users/{user_id}/roles` - Update user roles
- `GET /api/v1/users/stats/overview` - User statistics
- `POST /api/v1/users/password-reset/request` - Request password reset
- `POST /api/v1/users/password-reset/confirm` - Confirm password reset
- `POST /api/v1/users/email-verification/request` - Request email verification
- `POST /api/v1/users/email-verification/confirm` - Confirm email verification

### Roles & Permissions (`/api/v1/roles`) - 15+ endpoints
- Role CRUD operations
- Scope management
- Permission checking (single and bulk)
- User permission queries
- Role statistics

### Service Clients (`/api/v1/service-clients`) - 10+ endpoints
- Client CRUD operations
- Secret rotation
- Scope management
- Permission queries
- Health checks and statistics

### Sessions (`/api/v1/sessions`) - 6 endpoints
- `GET /api/v1/sessions/` - List user sessions
- `POST /api/v1/sessions/{session_id}/renew` - Renew session
- `DELETE /api/v1/sessions/{session_id}` - Invalidate session
- `DELETE /api/v1/sessions/` - Invalidate all sessions
- `GET /api/v1/sessions/stats` - Session statistics (admin)
- `POST /api/v1/sessions/cleanup` - Cleanup expired sessions (admin)

### Admin (`/api/v1/admin`) - 15+ endpoints
- Dashboard statistics
- System health monitoring
- Security event logs
- Audit activity logs
- Maintenance operations
- Configuration management
- Error log access

## 🧪 Test Scenarios

### Happy Path Tests
- Standard user registration and login flow
- Service client authentication and API access
- Role-based permission enforcement
- Session management lifecycle

### Error Handling Tests
- Invalid credentials
- Expired tokens
- Insufficient permissions
- Rate limit exceeded
- Malformed requests
- Database connectivity issues

### Edge Cases
- Concurrent login attempts
- Token refresh race conditions
- Large payload handling
- Special characters in inputs
- Boundary value testing

### Performance Tests
- **Load Testing**: 100+ concurrent users
- **Stress Testing**: Peak load scenarios
- **Endurance Testing**: Extended operation periods
- **Response Time**: < 200ms for most endpoints
- **Throughput**: Requests per second benchmarks

## 📈 Success Criteria

### Functional Requirements
- ✅ All documented endpoints return expected responses
- ✅ Authentication flows work correctly
- ✅ Authorization is properly enforced
- ✅ Data validation prevents invalid inputs
- ✅ Error responses are properly formatted

### Performance Requirements
- ✅ Health endpoint responds < 50ms
- ✅ Authentication endpoints respond < 200ms
- ✅ CRUD operations respond < 500ms
- ✅ System handles 100+ concurrent users
- ✅ No memory leaks during extended operation

### Security Requirements
- ✅ Rate limiting prevents abuse
- ✅ JWT tokens are properly validated
- ✅ Sensitive data is not exposed in logs
- ✅ CORS policies are enforced
- ✅ Input sanitization prevents injection attacks

## 🚀 Test Execution Plan

### Phase 1: Infrastructure Validation (5 minutes)
1. Verify all Docker containers are healthy
2. Test database connectivity and basic queries
3. Validate Redis connectivity and caching
4. Check Nginx routing and SSL configuration

### Phase 2: Basic Endpoint Testing (15 minutes)
1. Health and monitoring endpoints
2. Authentication flow validation
3. Basic CRUD operations for each resource type
4. Permission and authorization checks

### Phase 3: Comprehensive Functional Testing (30 minutes)
1. All documented endpoints with various scenarios
2. Error handling and edge cases
3. Data validation and sanitization
4. Complex multi-step workflows

### Phase 4: Security and Performance Testing (20 minutes)
1. Rate limiting enforcement
2. Security vulnerability checks
3. Load testing with concurrent users
4. Response time benchmarking

### Phase 5: Integration and End-to-End Testing (15 minutes)
1. Complete user lifecycle scenarios
2. Service-to-service authentication flows
3. Admin operations and monitoring
4. System recovery and failover scenarios

## 📊 Test Reporting

### Metrics Collected
- **Endpoint Coverage**: Percentage of endpoints tested
- **Success Rate**: Percentage of tests passing
- **Response Times**: Average, median, 95th percentile
- **Error Rates**: By endpoint and error type
- **Performance Metrics**: Throughput, concurrent users supported

### Report Format
- Executive summary with pass/fail status
- Detailed results by test category
- Performance benchmarks and comparisons
- Security validation results
- Recommendations for improvements

## 🔧 Test Configuration

### Environment Variables
```bash
# Test target configuration
PERMISO_BASE_URL=https://localhost:443
PERMISO_HTTP_URL=http://localhost:80

# Test credentials
TEST_ADMIN_USERNAME=admin
TEST_ADMIN_PASSWORD=admin_password
TEST_USER_USERNAME=testuser
TEST_USER_PASSWORD=test_password

# Service client for testing
TEST_CLIENT_ID=test-client
TEST_CLIENT_SECRET=test-secret

# Test configuration
TEST_CONCURRENT_USERS=100
TEST_DURATION_SECONDS=300
TEST_TIMEOUT_SECONDS=30
```

### Test Data Requirements
- Pre-configured admin user
- Test service client with appropriate scopes
- Sample roles and permissions
- Test user accounts for various scenarios

## 🏃‍♂️ Quick Start

```bash
# Navigate to test directory
cd tests/deploy

# Install test dependencies
pip install -r requirements.txt

# Run infrastructure tests
python -m pytest test_infrastructure.py -v

# Run all endpoint tests
python -m pytest test_endpoints.py -v

# Run performance tests
python -m pytest test_performance.py -v

# Run complete test suite
python -m pytest . -v --html=report.html
```

## 📝 Test Maintenance

### Regular Updates Required
- Update test data when API changes
- Adjust performance benchmarks based on infrastructure
- Review security tests for new vulnerabilities
- Update documentation with new endpoints

### Monitoring Integration
- Integrate with CI/CD pipelines
- Set up automated test execution schedules
- Configure alerts for test failures
- Track test metrics over time