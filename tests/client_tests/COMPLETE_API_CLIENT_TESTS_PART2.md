# Complete API Client Tests - Part 2: Service Integration & Advanced Patterns

## Remaining Administrative Endpoints

### 64. Error Logs

**Endpoint**: `GET /api/v1/admin/logs/errors`

```bash
# Get error logs
curl -k -X GET "${BASE_URL}${API_BASE}/admin/logs/errors" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Filter error logs
curl -k -X GET "${BASE_URL}${API_BASE}/admin/logs/errors?level=ERROR&hours=24" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

## System Endpoints

### 65. Health Check

**Endpoint**: `GET /health`

```bash
# System health check (no authentication required)
curl -k -X GET "${BASE_URL}/health"
```

### 66. Root Information

**Endpoint**: `GET /`

```bash
# Get API root information (no authentication required)
curl -k -X GET "${BASE_URL}/"
```

## Service-to-Service Integration

### Complete Service Client Integration Example

Here's a comprehensive example of how to integrate with the Permiso API from a service application:

#### 1. Service Client Setup

```python
#!/usr/bin/env python3
"""
Permiso API Service Client Integration Example
"""

import requests
import json
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PermisoServiceClient:
    """Service client for Permiso API integration."""
    
    def __init__(self, base_url: str, client_id: str, client_secret: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip('/')
        self.api_base = "/api/v1"
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify_ssl = verify_ssl
        self.access_token = None
        self.token_expires_at = None
        
        # Configure session
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'PermisoServiceClient/1.0'
        })
    
    def authenticate(self) -> bool:
        """Authenticate using client credentials flow."""
        try:
            url = f"{self.base_url}{self.api_base}/auth/service-token"
            data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'client_credentials'
            }
            
            response = self.session.post(
                url, 
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.access_token = token_data['access_token']
                expires_in = token_data.get('expires_in', 900)  # Default 15 minutes
                self.token_expires_at = datetime.now() + timedelta(seconds=expires_in - 60)  # Refresh 1 minute early
                
                # Update session headers
                self.session.headers['Authorization'] = f"Bearer {self.access_token}"
                
                logger.info("Successfully authenticated with Permiso API")
                return True
            else:
                logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def ensure_authenticated(self) -> bool:
        """Ensure we have a valid access token."""
        if not self.access_token or (self.token_expires_at and datetime.now() >= self.token_expires_at):
            return self.authenticate()
        return True
    
    def make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make authenticated request to API."""
        if not self.ensure_authenticated():
            raise Exception("Failed to authenticate")
        
        url = f"{self.base_url}{self.api_base}{endpoint}"
        return self.session.request(method, url, **kwargs)
    
    # User Management Methods
    def create_user(self, user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create a new user."""
        try:
            response = self.make_request('POST', '/users', json=user_data)
            if response.status_code == 201:
                return response.json()
            else:
                logger.error(f"Failed to create user: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return None
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        try:
            response = self.make_request('GET', f'/users/{user_id}')
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get user: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error getting user: {e}")
            return None
    
    def update_user(self, user_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update user."""
        try:
            response = self.make_request('PUT', f'/users/{user_id}', json=update_data)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to update user: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error updating user: {e}")
            return None
    
    def list_users(self, **filters) -> Optional[Dict[str, Any]]:
        """List users with optional filters."""
        try:
            response = self.make_request('GET', '/users', params=filters)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to list users: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error listing users: {e}")
            return None
    
    # Permission Management Methods
    def check_user_permission(self, user_id: str, resource: str, action: str) -> bool:
        """Check if user has specific permission."""
        try:
            data = {
                'user_id': user_id,
                'resource': resource,
                'action': action
            }
            response = self.make_request('POST', '/roles/permissions/check', json=data)
            if response.status_code == 200:
                result = response.json()
                return result.get('allowed', False)
            else:
                logger.error(f"Failed to check permission: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error checking permission: {e}")
            return False
    
    def get_user_permissions(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get all permissions for a user."""
        try:
            response = self.make_request('GET', f'/roles/permissions/user/{user_id}')
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get user permissions: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error getting user permissions: {e}")
            return None
    
    # Role Management Methods
    def create_role(self, role_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create a new role."""
        try:
            response = self.make_request('POST', '/roles', json=role_data)
            if response.status_code == 201:
                return response.json()
            else:
                logger.error(f"Failed to create role: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error creating role: {e}")
            return None
    
    def assign_user_roles(self, user_id: str, role_ids: list) -> bool:
        """Assign roles to a user."""
        try:
            data = {'role_ids': role_ids}
            response = self.make_request('PUT', f'/users/{user_id}/roles', json=data)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error assigning roles: {e}")
            return False

# Usage Example
def main():
    """Example usage of the service client."""
    
    # Initialize client
    client = PermisoServiceClient(
        base_url="https://localhost:443",
        client_id="your-service-client-id",
        client_secret="your-service-client-secret",
        verify_ssl=False  # Only for testing
    )
    
    # Authenticate
    if not client.authenticate():
        logger.error("Failed to authenticate")
        return
    
    # Example: Create a user
    user_data = {
        "username": "service_created_user",
        "email": "service@example.com",
        "password": "SecurePass123!",
        "first_name": "Service",
        "last_name": "User",
        "is_active": True,
        "is_verified": True
    }
    
    user = client.create_user(user_data)
    if user:
        logger.info(f"Created user: {user['id']}")
        
        # Example: Check user permission
        has_permission = client.check_user_permission(
            user['id'], 
            'posts', 
            'read'
        )
        logger.info(f"User has read:posts permission: {has_permission}")
        
        # Example: Get user permissions
        permissions = client.get_user_permissions(user['id'])
        if permissions:
            logger.info(f"User permissions: {permissions}")

if __name__ == "__main__":
    main()
```

#### 2. Service Client Configuration

```bash
# Environment variables for service client
export PERMISO_BASE_URL="https://localhost:443"
export PERMISO_CLIENT_ID="your-service-client-id"
export PERMISO_CLIENT_SECRET="your-service-client-secret"
export PERMISO_VERIFY_SSL="false"  # Only for testing
```

#### 3. Service Client Shell Script Examples

```bash
#!/bin/bash
# service_client_examples.sh

# Configuration
BASE_URL="https://localhost:443"
API_BASE="/api/v1"
CLIENT_ID="your-service-client-id"
CLIENT_SECRET="your-service-client-secret"

# Function to get service token
get_service_token() {
    curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&grant_type=client_credentials" \
        | jq -r '.access_token'
}

# Function to make authenticated API call
api_call() {
    local method=$1
    local endpoint=$2
    local data=$3
    local token=$(get_service_token)
    
    if [ -n "$data" ]; then
        curl -k -s -X "$method" "${BASE_URL}${API_BASE}${endpoint}" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$data"
    else
        curl -k -s -X "$method" "${BASE_URL}${API_BASE}${endpoint}" \
            -H "Authorization: Bearer $token"
    fi
}

# Example: Create user via service
create_user_via_service() {
    local user_data='{
        "username": "service_user_001",
        "email": "serviceuser@example.com",
        "password": "ServicePass123!",
        "first_name": "Service",
        "last_name": "User",
        "is_active": true,
        "is_verified": true
    }'
    
    echo "Creating user via service..."
    api_call "POST" "/users" "$user_data" | jq '.'
}

# Example: List users via service
list_users_via_service() {
    echo "Listing users via service..."
    api_call "GET" "/users?page=1&per_page=10" | jq '.'
}

# Example: Check user permissions via service
check_permissions_via_service() {
    local user_id=$1
    local permission_data='{
        "user_id": "'$user_id'",
        "resource": "posts",
        "action": "read"
    }'
    
    echo "Checking permissions for user $user_id..."
    api_call "POST" "/roles/permissions/check" "$permission_data" | jq '.'
}

# Example: Get system health via service
get_system_health() {
    echo "Getting system health..."
    api_call "GET" "/admin/system/health" | jq '.'
}

# Run examples
echo "=== Service Client Examples ==="
create_user_via_service
echo ""
list_users_via_service
echo ""
get_system_health
```

## Error Handling

### Common Error Responses

```bash
# 401 Unauthorized
{
  "error": "invalid_token",
  "error_description": "The access token provided is expired, revoked, malformed, or invalid"
}

# 403 Forbidden
{
  "error": "insufficient_scope",
  "error_description": "The request requires higher privileges than provided by the access token"
}

# 404 Not Found
{
  "error": "not_found",
  "error_description": "The requested resource was not found"
}

# 409 Conflict
{
  "error": "conflict",
  "error_description": "Username already exists"
}

# 422 Validation Error
{
  "error": "validation_error",
  "error_description": "Request validation failed",
  "details": [
    {
      "loc": ["body", "email"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}

# 429 Rate Limited
{
  "error": "rate_limit_exceeded",
  "error_description": "Too many requests. Please try again later.",
  "retry_after": 60
}

# 500 Internal Server Error
{
  "error": "internal_server_error",
  "error_description": "An internal server error occurred"
}
```

### Error Handling in Shell Scripts

```bash
#!/bin/bash
# error_handling_example.sh

# Function to handle API responses
handle_response() {
    local response=$1
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n -1)
    
    case $http_code in
        200|201|204)
            echo "Success: $body"
            return 0
            ;;
        400)
            echo "Bad Request: $(echo "$body" | jq -r '.error_description // .detail // "Invalid request"')"
            return 1
            ;;
        401)
            echo "Unauthorized: $(echo "$body" | jq -r '.error_description // "Authentication required"')"
            return 1
            ;;
        403)
            echo "Forbidden: $(echo "$body" | jq -r '.error_description // "Access denied"')"
            return 1
            ;;
        404)
            echo "Not Found: $(echo "$body" | jq -r '.error_description // "Resource not found"')"
            return 1
            ;;
        409)
            echo "Conflict: $(echo "$body" | jq -r '.error_description // "Resource conflict"')"
            return 1
            ;;
        422)
            echo "Validation Error: $(echo "$body" | jq -r '.error_description // "Validation failed"')"
            echo "Details: $(echo "$body" | jq -r '.details // empty')"
            return 1
            ;;
        429)
            echo "Rate Limited: $(echo "$body" | jq -r '.error_description // "Too many requests"')"
            local retry_after=$(echo "$body" | jq -r '.retry_after // 60')
            echo "Retry after: $retry_after seconds"
            return 1
            ;;
        *)
            echo "Error $http_code: $body"
            return 1
            ;;
    esac
}

# Example usage
make_api_call() {
    local response=$(curl -k -s -w "\n%{http_code}" -X GET "${BASE_URL}${API_BASE}/users/me" \
        -H "Authorization: Bearer $USER_TOKEN")
    
    handle_response "$response"
}
```

## Complete Test Scenarios

### Scenario 1: User Registration and Authentication Flow

```bash
#!/bin/bash
# scenario_1_user_flow.sh

echo "=== Scenario 1: Complete User Flow ==="

# Step 1: Register new user
echo "Step 1: Registering new user..."
REGISTER_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X POST "${BASE_URL}${API_BASE}/users/register" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "testuser_'$(date +%s)'",
        "email": "testuser'$(date +%s)'@example.com",
        "password": "TestPass123!",
        "first_name": "Test",
        "last_name": "User"
    }')

if ! handle_response "$REGISTER_RESPONSE"; then
    echo "Registration failed, exiting..."
    exit 1
fi

# Extract user data
USER_DATA=$(echo "$REGISTER_RESPONSE" | head -n -1)
USERNAME=$(echo "$USER_DATA" | jq -r '.username')
USER_EMAIL=$(echo "$USER_DATA" | jq -r '.email')

echo "Registered user: $USERNAME ($USER_EMAIL)"

# Step 2: Login with new user
echo "Step 2: Logging in with new user..."
LOGIN_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X POST "${BASE_URL}${API_BASE}/auth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${USERNAME}&password=TestPass123!&grant_type=password")

if ! handle_response "$LOGIN_RESPONSE"; then
    echo "Login failed, exiting..."
    exit 1
fi

# Extract tokens
TOKEN_DATA=$(echo "$LOGIN_RESPONSE" | head -n -1)
ACCESS_TOKEN=$(echo "$TOKEN_DATA" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$TOKEN_DATA" | jq -r '.refresh_token')

echo "Login successful, got access token"

# Step 3: Get user profile
echo "Step 3: Getting user profile..."
PROFILE_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X GET "${BASE_URL}${API_BASE}/users/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

if ! handle_response "$PROFILE_RESPONSE"; then
    echo "Profile retrieval failed"
else
    echo "Profile retrieved successfully"
fi

# Step 4: Update profile
echo "Step 4: Updating user profile..."
UPDATE_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X PUT "${BASE_URL}${API_BASE}/users/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "first_name": "Updated",
        "last_name": "Name",
        "bio": "Updated via API test"
    }')

if ! handle_response "$UPDATE_RESPONSE"; then
    echo "Profile update failed"
else
    echo "Profile updated successfully"
fi

# Step 5: Refresh token
echo "Step 5: Refreshing access token..."
REFRESH_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X POST "${BASE_URL}${API_BASE}/auth/refresh" \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}")

if ! handle_response "$REFRESH_RESPONSE"; then
    echo "Token refresh failed"
else
    echo "Token refreshed successfully"
    NEW_TOKEN_DATA=$(echo "$REFRESH_RESPONSE" | head -n -1)
    NEW_ACCESS_TOKEN=$(echo "$NEW_TOKEN_DATA" | jq -r '.access_token')
    ACCESS_TOKEN=$NEW_ACCESS_TOKEN
fi

# Step 6: Logout
echo "Step 6: Logging out..."
LOGOUT_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X POST "${BASE_URL}${API_BASE}/auth/logout" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

if ! handle_response "$LOGOUT_RESPONSE"; then
    echo "Logout failed"
else
    echo "Logout successful"
fi

echo "=== Scenario 1 Complete ==="
```

### Scenario 2: Admin User Management

```bash
#!/bin/bash
# scenario_2_admin_management.sh

echo "=== Scenario 2: Admin User Management ==="

# Get admin token
echo "Getting admin token..."
ADMIN_TOKEN=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${ADMIN_USERNAME}&password=${ADMIN_PASSWORD}&grant_type=password" \
    | jq -r '.access_token')

if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo "Failed to get admin token"
    exit 1
fi

# Step 1: Create user as admin
echo "Step 1: Creating user as admin..."
CREATE_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X POST "${BASE_URL}${API_BASE}/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "adminuser_'$(date +%s)'",
        "email": "adminuser'$(date +%s)'@example.com",
        "password": "AdminPass123!",
        "first_name": "Admin",
        "last_name": "Created",
        "is_active": true,
        "is_verified": true
    }')

if ! handle_response "$CREATE_RESPONSE"; then
    echo "User creation failed, exiting..."
    exit 1
fi

# Extract user ID
USER_DATA=$(echo "$CREATE_RESPONSE" | head -n -1)
USER_ID=$(echo "$USER_DATA" | jq -r '.id')
echo "Created user with ID: $USER_ID"

# Step 2: List users
echo "Step 2: Listing users..."
LIST_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X GET "${BASE_URL}${API_BASE}/users?page=1&per_page=5" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

if ! handle_response "$LIST_RESPONSE"; then
    echo "User listing failed"
else
    LIST_DATA=$(echo "$LIST_RESPONSE" | head -n -1)
    TOTAL_USERS=$(echo "$LIST_DATA" | jq -r '.total')
    echo "Total users: $TOTAL_USERS"
fi

# Step 3: Update user
echo "Step 3: Updating user..."
UPDATE_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X PUT "${BASE_URL}${API_BASE}/users/$USER_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "first_name": "Updated Admin",
        "last_name": "User",
        "is_active": true
    }')

if ! handle_response "$UPDATE_RESPONSE"; then
    echo "User update failed"
else
    echo "User updated successfully"
fi

# Step 4: Get user statistics
echo "Step 4: Getting user statistics..."
STATS_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X GET "${BASE_URL}${API_BASE}/users/stats/overview" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

if ! handle_response "$STATS_RESPONSE"; then
    echo "Statistics retrieval failed"
else
    STATS_DATA=$(echo "$STATS_RESPONSE" | head -n -1)
    echo "User statistics: $(echo "$STATS_DATA" | jq -c '.')"
fi

# Step 5: Delete user
echo "Step 5: Deleting user..."
DELETE_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X DELETE "${BASE_URL}${API_BASE}/users/$USER_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

if ! handle_response "$DELETE_RESPONSE"; then
    echo "User deletion failed"
else
    echo "User deleted successfully"
fi

echo "=== Scenario 2 Complete ==="
```

### Scenario 3: Service Client Integration

```bash
#!/bin/bash
# scenario_3_service_client.sh

echo "=== Scenario 3: Service Client Integration ==="

# Step 1: Authenticate as service client
echo "Step 1: Authenticating as service client..."
SERVICE_TOKEN_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&grant_type=client_credentials")

if ! handle_response "$SERVICE_TOKEN_RESPONSE"; then
    echo "Service authentication failed, exiting..."
    exit 1
fi

# Extract service token
TOKEN_DATA=$(echo "$SERVICE_TOKEN_RESPONSE" | head -n -1)
SERVICE_TOKEN=$(echo "$TOKEN_DATA" | jq -r '.access_token')
echo "Service authentication successful"

# Step 2: Create user via service
echo "Step 2: Creating user via service..."
SERVICE_CREATE_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X POST "${BASE_URL}${API_BASE}/users" \
    -H "Authorization: Bearer $SERVICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "serviceuser_'$(date +%s)'",
        "email": "serviceuser'$(date +%s)'@example.com",
        "password": "ServicePass123!",
        "first_name": "Service",
        "last_name": "Created",
        "is_active": true,
        "is_verified": true
    }')

if ! handle_response "$SERVICE_CREATE_RESPONSE"; then
    echo "Service user creation failed"
else
    SERVICE_USER_DATA=$(echo "$SERVICE_CREATE_RESPONSE" | head -n -1)
    SERVICE_USER_ID=$(echo "$SERVICE_USER_DATA" | jq -r '.id')
    echo "Service created user with ID: $SERVICE_USER_ID"
fi

# Step 3: Check permissions via service
if [ -n "$SERVICE_USER_ID" ]; then
    echo "Step 3: Checking user permissions via service..."
    PERMISSION_CHECK_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X POST "${BASE_URL}${API_BASE}/roles/permissions/check" \
        -H "Authorization: Bearer $SERVICE_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "user_id": "'$SERVICE_USER_ID'",
            "resource": "posts",
            "action": "read"
        }')
    
    if ! handle_response "$PERMISSION_CHECK_RESPONSE"; then
        echo "Permission check failed"
    else
        PERMISSION_DATA=$(echo "$PERMISSION_CHECK_RESPONSE" | head -n -1)
        HAS_PERMISSION=$(echo "$PERMISSION_DATA" | jq -r '.allowed')
        echo "User has read:posts permission: $HAS_PERMISSION"
    fi
fi

# Step 4: Get system health via service
echo "Step 4: Getting system health via service..."
HEALTH_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X GET "${BASE_URL}${API_BASE}/admin/system/health" \
    -H "Authorization: Bearer $SERVICE_TOKEN")

if ! handle_response "$HEALTH_RESPONSE"; then
    echo "Health check failed"
else
    HEALTH_DATA=$(echo "$HEALTH_RESPONSE" | head -n -1)
    SYSTEM_STATUS=$(echo "$HEALTH_DATA" | jq -r '.status')
    echo "System health status: $SYSTEM_STATUS"
fi

echo "=== Scenario 3 Complete ==="
```

## Test Execution Scripts

### Master Test Runner

```bash
#!/bin/bash
# run_all_tests.sh

echo "=========================================="
echo "Permiso API Complete Test Suite"
echo "=========================================="

# Source configuration
source ./test_config.sh

# Source helper functions
source ./test_helpers.sh

# Initialize test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run test scenario
run_test_scenario() {
    local scenario_name=$1
    local scenario_script=$2
    
    echo ""
    echo "Running: $scenario_name"
    echo "----------------------------------------"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if bash "$scenario_script"; then
        echo "✅ PASSED: $scenario_name"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "❌ FAILED: $scenario_name"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Run all test scenarios
run_test_scenario "User Registration and Authentication Flow" "./scenario_1_user_flow.sh"
run_test_scenario "Admin User Management" "./scenario_2_admin_management.sh"
run_test_scenario "Service Client Integration" "./scenario_3_service_client.sh"

# Print summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Total Tests: $TOTAL_TESTS"
echo "Passed: $PASSED_TESTS"
echo "Failed: $FAILED_TESTS"
echo "Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"

if [ $FAILED_TESTS -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "⚠️  Some tests failed"
    exit 1
fi
```

### Test Configuration

```bash
#!/bin/bash
# test_config.sh

# API Configuration
export BASE_URL="https://localhost:443"
export API_BASE="/api/v1"

# Test Credentials
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="ProductionPassword123!"
export USER_USERNAME="testuser"
export USER_PASSWORD="UserPass123!"
export CLIENT_ID="test-client-001"
export CLIENT_