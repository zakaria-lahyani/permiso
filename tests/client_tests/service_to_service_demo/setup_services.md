# Service Registration Setup

This document shows how to register both `service_brain` and `service_executer` with Permiso.

## 🔧 Prerequisites

```bash
# Environment setup
export BASE_URL="https://localhost:443"
export API_BASE="/api/v1"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="ProductionPassword123!"

# Service identifiers
export SERVICE_BRAIN_ID="service-brain-001"
export SERVICE_BRAIN_SECRET="brain-secret-$(date +%s)"
export SERVICE_EXECUTER_ID="service-executer-001"
export SERVICE_EXECUTER_SECRET="executer-secret-$(date +%s)"
```

## 🎯 Step 1: Get Admin Token

```bash
# Authenticate as admin to register services
ADMIN_TOKEN=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${ADMIN_USERNAME}&password=${ADMIN_PASSWORD}&grant_type=password" \
  | jq -r '.access_token')

echo "Admin token: ${ADMIN_TOKEN:0:20}..."
```

## 🧠 Step 2: Register service_brain (Initiator Service)

```bash
# Create service_brain client
BRAIN_RESPONSE=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/service-clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Service Brain",
    "description": "Initiator service for service-to-service communication",
    "client_type": "confidential",
    "is_active": true,
    "is_trusted": true,
    "contact_email": "admin@example.com",
    "access_token_lifetime": 3600,
    "rate_limit_per_minute": 100,
    "rate_limit_per_hour": 5000
  }')

echo "service_brain registration response:"
echo "$BRAIN_RESPONSE" | jq '.'

# Extract client credentials
SERVICE_BRAIN_ID=$(echo "$BRAIN_RESPONSE" | jq -r '.client.client_id')
SERVICE_BRAIN_SECRET=$(echo "$BRAIN_RESPONSE" | jq -r '.client_secret')

echo "service_brain registered:"
echo "  Client ID: $SERVICE_BRAIN_ID"
echo "  Client Secret: ${SERVICE_BRAIN_SECRET:0:20}..."
```

## ⚡ Step 3: Register service_executer (Receiver Service)

```bash
# Create service_executer client
EXECUTER_RESPONSE=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/service-clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Service Executer",
    "description": "Receiver service for service-to-service communication",
    "client_type": "confidential",
    "is_active": true,
    "is_trusted": true,
    "contact_email": "admin@example.com",
    "access_token_lifetime": 3600,
    "rate_limit_per_minute": 200,
    "rate_limit_per_hour": 10000
  }')

echo "service_executer registration response:"
echo "$EXECUTER_RESPONSE" | jq '.'

# Extract client credentials
SERVICE_EXECUTER_ID=$(echo "$EXECUTER_RESPONSE" | jq -r '.client.client_id')
SERVICE_EXECUTER_SECRET=$(echo "$EXECUTER_RESPONSE" | jq -r '.client_secret')

echo "service_executer registered:"
echo "  Client ID: $SERVICE_EXECUTER_ID"
echo "  Client Secret: ${SERVICE_EXECUTER_SECRET:0:20}..."
```

## 🔐 Step 4: Create Required Scopes

```bash
# Create service communication scopes
echo "Creating required scopes..."

# Scope 1: API Read access
API_READ_SCOPE=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/roles/scopes" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "api:read",
    "description": "Read access to API resources",
    "resource": "api",
    "action": "read"
  }')

API_READ_SCOPE_ID=$(echo "$API_READ_SCOPE" | jq -r '.id')
echo "Created api:read scope (ID: $API_READ_SCOPE_ID)"

# Scope 2: API Write access
API_WRITE_SCOPE=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/roles/scopes" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "api:write",
    "description": "Write access to API resources",
    "resource": "api",
    "action": "write"
  }')

API_WRITE_SCOPE_ID=$(echo "$API_WRITE_SCOPE" | jq -r '.id')
echo "Created api:write scope (ID: $API_WRITE_SCOPE_ID)"

# Scope 3: Service communication
SERVICE_COMM_SCOPE=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/roles/scopes" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "service:communicate",
    "description": "Service-to-service communication",
    "resource": "service",
    "action": "communicate"
  }')

SERVICE_COMM_SCOPE_ID=$(echo "$SERVICE_COMM_SCOPE" | jq -r '.id')
echo "Created service:communicate scope (ID: $SERVICE_COMM_SCOPE_ID)"
```

## 🎯 Step 5: Assign Scopes to Services

```bash
# Assign scopes to service_brain
echo "Assigning scopes to service_brain..."
curl -k -s -X PUT "${BASE_URL}${API_BASE}/service-clients/${SERVICE_BRAIN_ID}/scopes" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"scope_ids\": [${API_READ_SCOPE_ID}, ${API_WRITE_SCOPE_ID}, ${SERVICE_COMM_SCOPE_ID}]
  }" | jq '.'

# Assign scopes to service_executer
echo "Assigning scopes to service_executer..."
curl -k -s -X PUT "${BASE_URL}${API_BASE}/service-clients/${SERVICE_EXECUTER_ID}/scopes" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"scope_ids\": [${API_READ_SCOPE_ID}, ${API_WRITE_SCOPE_ID}, ${SERVICE_COMM_SCOPE_ID}]
  }" | jq '.'
```

## ✅ Step 6: Verify Service Registration

```bash
# Verify service_brain registration
echo "Verifying service_brain registration..."
curl -k -s -X GET "${BASE_URL}${API_BASE}/service-clients/${SERVICE_BRAIN_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq '{
    client_id: .client_id,
    name: .name,
    is_active: .is_active,
    is_trusted: .is_trusted,
    scopes: [.scopes[].name]
  }'

# Verify service_executer registration
echo "Verifying service_executer registration..."
curl -k -s -X GET "${BASE_URL}${API_BASE}/service-clients/${SERVICE_EXECUTER_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq '{
    client_id: .client_id,
    name: .name,
    is_active: .is_active,
    is_trusted: .is_trusted,
    scopes: [.scopes[].name]
  }'
```

## 🧪 Step 7: Test Service Authentication

```bash
# Test service_brain authentication
echo "Testing service_brain authentication..."
BRAIN_TOKEN_RESPONSE=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${SERVICE_BRAIN_ID}&client_secret=${SERVICE_BRAIN_SECRET}&grant_type=client_credentials")

echo "service_brain token response:"
echo "$BRAIN_TOKEN_RESPONSE" | jq '.'

BRAIN_TOKEN=$(echo "$BRAIN_TOKEN_RESPONSE" | jq -r '.access_token')
echo "service_brain token: ${BRAIN_TOKEN:0:20}..."

# Test service_executer authentication
echo "Testing service_executer authentication..."
EXECUTER_TOKEN_RESPONSE=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${SERVICE_EXECUTER_ID}&client_secret=${SERVICE_EXECUTER_SECRET}&grant_type=client_credentials")

echo "service_executer token response:"
echo "$EXECUTER_TOKEN_RESPONSE" | jq '.'

EXECUTER_TOKEN=$(echo "$EXECUTER_TOKEN_RESPONSE" | jq -r '.access_token')
echo "service_executer token: ${EXECUTER_TOKEN:0:20}..."
```

## 📋 Step 8: Save Configuration

```bash
# Save service configuration for later use
cat > service_config.env << EOF
# Service Configuration Generated $(date)
export BASE_URL="${BASE_URL}"
export API_BASE="${API_BASE}"

# service_brain configuration
export SERVICE_BRAIN_ID="${SERVICE_BRAIN_ID}"
export SERVICE_BRAIN_SECRET="${SERVICE_BRAIN_SECRET}"

# service_executer configuration
export SERVICE_EXECUTER_ID="${SERVICE_EXECUTER_ID}"
export SERVICE_EXECUTER_SECRET="${SERVICE_EXECUTER_SECRET}"

# Scope IDs
export API_READ_SCOPE_ID="${API_READ_SCOPE_ID}"
export API_WRITE_SCOPE_ID="${API_WRITE_SCOPE_ID}"
export SERVICE_COMM_SCOPE_ID="${SERVICE_COMM_SCOPE_ID}"
EOF

echo "Configuration saved to service_config.env"
echo "Source this file in future sessions: source service_config.env"
```

## 🔍 Troubleshooting

### Common Issues

1. **Service registration fails**
   ```bash
   # Check admin token validity
   curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/introspect" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}" \
     -H "Content-Type: application/json" \
     -d "{\"token\": \"${ADMIN_TOKEN}\"}" | jq '.active'
   ```

2. **Scope creation fails**
   ```bash
   # List existing scopes to avoid duplicates
   curl -k -s -X GET "${BASE_URL}${API_BASE}/roles/scopes" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq '.scopes[].name'
   ```

3. **Service authentication fails**
   ```bash
   # Verify service client exists and is active
   curl -k -s -X GET "${BASE_URL}${API_BASE}/service-clients/${SERVICE_BRAIN_ID}" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq '{is_active, is_trusted}'
   ```

## 📊 Expected Results

After successful setup:

- ✅ Two service clients registered with Permiso
- ✅ Three scopes created: `api:read`, `api:write`, `service:communicate`
- ✅ Both services can authenticate and receive JWT tokens
- ✅ Tokens contain the assigned scopes
- ✅ Configuration saved for future use

## 🔄 Alternative: Direct Database Registration

For development/testing, services can be registered directly in the database:

```sql
-- Insert service clients directly
INSERT INTO service_clients (
    client_id, name, client_secret_hash, description, 
    client_type, is_active, is_trusted, created_at
) VALUES 
(
    'service-brain-001', 
    'Service Brain', 
    '$2b$12$hashed_secret_here', 
    'Initiator service',
    'confidential', 
    true, 
    true, 
    NOW()
),
(
    'service-executer-001', 
    'Service Executer', 
    '$2b$12$hashed_secret_here', 
    'Receiver service',
    'confidential', 
    true, 
    true, 
    NOW()
);
```

This completes the service registration setup. Both services are now ready for service-to-service authentication testing.