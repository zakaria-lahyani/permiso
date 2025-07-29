# Service-to-Service Authentication Demo

This demo shows complete service-to-service authentication between two services using Permiso:

- **`service_brain`**: The initiator service that sends authenticated requests
- **`service_executer`**: The receiver service that validates incoming requests

## 🏗️ Architecture Overview

```mermaid
graph TB
    A[service_brain] -->|1. Get Service Token| B[Permiso API]
    B -->|2. Return JWT Token| A
    A -->|3. Send Request with JWT| C[service_executer]
    C -->|4. Validate Token| B
    B -->|5. Token Valid/Invalid| C
    C -->|6. Response| A
```

## 📋 Demo Components

### Core Files
- [`setup_services.md`](./setup_services.md) - Service registration with Permiso
- [`service_brain_demo.md`](./service_brain_demo.md) - Initiator service implementation
- [`service_executer_demo.md`](./service_executer_demo.md) - Receiver service implementation
- [`test_scenarios.md`](./test_scenarios.md) - Complete test scenarios
- [`error_handling.md`](./error_handling.md) - Error handling patterns

### Test Scripts
- [`run_demo.md`](./run_demo.md) - Complete demo execution guide

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Permiso API Configuration
export BASE_URL="https://localhost:443"
export API_BASE="/api/v1"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="ProductionPassword123!"

# Service Configuration
export SERVICE_BRAIN_ID="service-brain-001"
export SERVICE_BRAIN_SECRET="brain-secret-$(date +%s)"
export SERVICE_EXECUTER_ID="service-executer-001"
export SERVICE_EXECUTER_SECRET="executer-secret-$(date +%s)"
```

### 2. Register Services with Permiso

```bash
# Get admin token
ADMIN_TOKEN=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${ADMIN_USERNAME}&password=${ADMIN_PASSWORD}&grant_type=password" \
  | jq -r '.access_token')

# Register service_brain
curl -k -X POST "${BASE_URL}${API_BASE}/service-clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "'${SERVICE_BRAIN_ID}'",
    "name": "Service Brain",
    "description": "Initiator service for service-to-service communication",
    "client_type": "confidential",
    "is_active": true,
    "is_trusted": true,
    "scope_ids": [1, 2, 3]
  }'

# Register service_executer
curl -k -X POST "${BASE_URL}${API_BASE}/service-clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "'${SERVICE_EXECUTER_ID}'",
    "name": "Service Executer",
    "description": "Receiver service for service-to-service communication",
    "client_type": "confidential",
    "is_active": true,
    "is_trusted": true,
    "scope_ids": [1, 2, 3]
  }'
```

### 3. Test Service-to-Service Flow

```bash
# service_brain gets token
BRAIN_TOKEN=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${SERVICE_BRAIN_ID}&client_secret=${SERVICE_BRAIN_SECRET}&grant_type=client_credentials" \
  | jq -r '.access_token')

# service_brain makes authenticated request to service_executer
# (In real scenario, this would be to service_executer's endpoint)
curl -k -X GET "${BASE_URL}${API_BASE}/users" \
  -H "Authorization: Bearer ${BRAIN_TOKEN}"
```

## 🔐 Authentication Flow

### 1. Service Registration
Both services must be registered with Permiso with appropriate scopes:
- `api:read` - Read access to API resources
- `api:write` - Write access to API resources
- `service:communicate` - Service-to-service communication

### 2. Token Acquisition
`service_brain` obtains a service token using OAuth2 client credentials flow:

```bash
POST /api/v1/auth/service-token
Content-Type: application/x-www-form-urlencoded

client_id=service-brain-001&client_secret=brain-secret&grant_type=client_credentials&scope=api:read api:write
```

### 3. Request Authentication
`service_brain` includes the JWT token in requests to `service_executer`:

```bash
GET /api/endpoint
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

### 4. Token Validation
`service_executer` validates the token by:
- **Option A**: Direct validation with Permiso introspection endpoint
- **Option B**: JWT signature verification using Permiso's public key

## ✅ Test Scenarios Covered

### Success Cases
- ✅ Valid token with correct scopes
- ✅ Token refresh and reuse
- ✅ Multiple concurrent requests

### Error Cases
- ❌ Missing Authorization header (401)
- ❌ Invalid token format (401)
- ❌ Expired token (401)
- ❌ Insufficient scopes (403)
- ❌ Revoked token (401)
- ❌ Invalid client credentials (401)

## 📊 Demo Results

The demo validates:
1. **Service Registration**: Both services successfully registered with Permiso
2. **Token Generation**: `service_brain` can obtain valid service tokens
3. **Request Authentication**: Tokens are properly included in requests
4. **Token Validation**: `service_executer` can validate tokens via Permiso
5. **Error Handling**: Proper error responses for various failure scenarios
6. **Scope Enforcement**: Access control based on granted scopes

## 🔧 Integration Patterns

### Direct Database Integration
Services can be registered directly in the database:

```sql
INSERT INTO service_clients (client_id, name, client_secret_hash, is_active, is_trusted)
VALUES ('service-brain-001', 'Service Brain', '$2b$12$...', true, true);
```

### API Integration
Services registered via Permiso API (recommended):

```bash
POST /api/v1/service-clients
Authorization: Bearer admin-token
Content-Type: application/json

{
  "client_id": "service-brain-001",
  "name": "Service Brain",
  "client_type": "confidential",
  "is_active": true,
  "scope_ids": [1, 2, 3]
}
```

This demo provides a complete, working example of service-to-service authentication using Permiso, with comprehensive error handling and validation scenarios.