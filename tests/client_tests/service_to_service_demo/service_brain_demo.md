# Service Brain Demo - Initiator Service

This document demonstrates how `service_brain` (the initiator service) authenticates with Permiso and makes requests to other services.

## 🧠 Service Brain Overview

`service_brain` is the **initiator service** that:
1. Authenticates with Permiso using client credentials
2. Obtains a JWT access token with required scopes
3. Makes authenticated requests to `service_executer`
4. Handles token refresh and error scenarios

## 🔧 Prerequisites

```bash
# Load service configuration
source service_config.env

# Or set manually:
export BASE_URL="https://localhost:443"
export API_BASE="/api/v1"
export SERVICE_BRAIN_ID="service-brain-001"
export SERVICE_BRAIN_SECRET="your-brain-secret"
```

## 🎯 Step 1: Service Authentication

### Basic Authentication

```bash
# service_brain authenticates with Permiso
echo "=== service_brain Authentication ==="

BRAIN_AUTH_RESPONSE=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${SERVICE_BRAIN_ID}&client_secret=${SERVICE_BRAIN_SECRET}&grant_type=client_credentials")

echo "Authentication response:"
echo "$BRAIN_AUTH_RESPONSE" | jq '.'

# Extract token
BRAIN_TOKEN=$(echo "$BRAIN_AUTH_RESPONSE" | jq -r '.access_token')
BRAIN_EXPIRES_IN=$(echo "$BRAIN_AUTH_RESPONSE" | jq -r '.expires_in')
BRAIN_SCOPES=$(echo "$BRAIN_AUTH_RESPONSE" | jq -r '.scope')

echo "service_brain authenticated successfully:"
echo "  Token: ${BRAIN_TOKEN:0:30}..."
echo "  Expires in: ${BRAIN_EXPIRES_IN} seconds"
echo "  Scopes: ${BRAIN_SCOPES}"
```

### Authentication with Specific Scopes

```bash
# Request specific scopes
echo "=== service_brain Authentication with Specific Scopes ==="

BRAIN_SCOPED_RESPONSE=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${SERVICE_BRAIN_ID}&client_secret=${SERVICE_BRAIN_SECRET}&grant_type=client_credentials&scope=api:read service:communicate")

echo "Scoped authentication response:"
echo "$BRAIN_SCOPED_RESPONSE" | jq '.'

BRAIN_SCOPED_TOKEN=$(echo "$BRAIN_SCOPED_RESPONSE" | jq -r '.access_token')
echo "Scoped token: ${BRAIN_SCOPED_TOKEN:0:30}..."
```

## 🚀 Step 2: Making Authenticated Requests

### Request to Permiso API (Simulating service_executer)

```bash
# service_brain makes authenticated request to get users (simulating service_executer endpoint)
echo "=== service_brain Making Authenticated Request ==="

USER_LIST_RESPONSE=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}\nRESPONSE_TIME:%{time_total}" \
  -X GET "${BASE_URL}${API_BASE}/users?page=1&per_page=5" \
  -H "Authorization: Bearer ${BRAIN_TOKEN}" \
  -H "X-Service-Name: service_brain" \
  -H "X-Request-ID: req_$(date +%s)")

echo "Request response:"
echo "$USER_LIST_RESPONSE"
```

### Request with Different Endpoints

```bash
# Test different API endpoints that service_executer might expose
echo "=== Testing Different Endpoints ==="

# 1. Get system health (public endpoint)
echo "1. Health check request:"
curl -k -s -X GET "${BASE_URL}/health" \
  -H "X-Service-Name: service_brain" | jq '.'

# 2. Get user profile (authenticated endpoint)
echo "2. User profile request:"
curl -k -s -X GET "${BASE_URL}${API_BASE}/users/me" \
  -H "Authorization: Bearer ${BRAIN_TOKEN}" \
  -H "X-Service-Name: service_brain" | jq '{id, username, email, roles}'

# 3. Check permissions (admin endpoint)
echo "3. Permission check request:"
curl -k -s -X POST "${BASE_URL}${API_BASE}/roles/permissions/check" \
  -H "Authorization: Bearer ${BRAIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-Service-Name: service_brain" \
  -d '{
    "user_id": "some-user-id",
    "resource": "posts",
    "action": "read"
  }' | jq '.'
```

## 🔄 Step 3: Token Management

### Token Introspection

```bash
# service_brain can introspect its own token
echo "=== Token Introspection ==="

TOKEN_INTROSPECT_RESPONSE=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/introspect" \
  -H "Authorization: Bearer ${BRAIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"${BRAIN_TOKEN}\"}")

echo "Token introspection:"
echo "$TOKEN_INTROSPECT_RESPONSE" | jq '.'

# Extract token info
TOKEN_ACTIVE=$(echo "$TOKEN_INTROSPECT_RESPONSE" | jq -r '.active')
TOKEN_CLIENT_ID=$(echo "$TOKEN_INTROSPECT_RESPONSE" | jq -r '.client_id')
TOKEN_SCOPES=$(echo "$TOKEN_INTROSPECT_RESPONSE" | jq -r '.scope')

echo "Token status:"
echo "  Active: $TOKEN_ACTIVE"
echo "  Client ID: $TOKEN_CLIENT_ID"
echo "  Scopes: $TOKEN_SCOPES"
```

### Token Refresh Strategy

```bash
# service_brain implements token refresh logic
echo "=== Token Refresh Strategy ==="

# Function to check if token needs refresh
check_token_expiry() {
    local token=$1
    local current_time=$(date +%s)
    local token_exp=$(echo "$token" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq -r '.exp // empty' 2>/dev/null)
    
    if [ -n "$token_exp" ] && [ "$token_exp" -gt "$current_time" ]; then
        echo "Token valid for $((token_exp - current_time)) seconds"
        return 0
    else
        echo "Token expired or invalid"
        return 1
    fi
}

# Function to refresh token
refresh_service_token() {
    echo "Refreshing service token..."
    local new_token_response=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "client_id=${SERVICE_BRAIN_ID}&client_secret=${SERVICE_BRAIN_SECRET}&grant_type=client_credentials")
    
    local new_token=$(echo "$new_token_response" | jq -r '.access_token')
    echo "New token: ${new_token:0:30}..."
    echo "$new_token"
}

# Check current token
if check_token_expiry "$BRAIN_TOKEN"; then
    echo "Current token is still valid"
else
    echo "Token needs refresh"
    BRAIN_TOKEN=$(refresh_service_token)
fi
```

## 🎭 Step 4: Service-to-Service Communication Simulation

### Simulated service_executer Endpoint

```bash
# Simulate how service_brain would call service_executer
echo "=== Simulated Service-to-Service Call ==="

# In a real scenario, this would be service_executer's endpoint
# For demo, we'll use Permiso API endpoints to simulate

simulate_service_call() {
    local endpoint=$1
    local method=$2
    local data=$3
    
    echo "service_brain calling service_executer endpoint: $endpoint"
    
    if [ -n "$data" ]; then
        curl -k -s -w "\nHTTP_STATUS:%{http_code}" \
          -X "$method" "${BASE_URL}${API_BASE}${endpoint}" \
          -H "Authorization: Bearer ${BRAIN_TOKEN}" \
          -H "Content-Type: application/json" \
          -H "X-Service-Name: service_brain" \
          -H "X-Target-Service: service_executer" \
          -H "X-Request-ID: req_$(date +%s)" \
          -d "$data"
    else
        curl -k -s -w "\nHTTP_STATUS:%{http_code}" \
          -X "$method" "${BASE_URL}${API_BASE}${endpoint}" \
          -H "Authorization: Bearer ${BRAIN_TOKEN}" \
          -H "X-Service-Name: service_brain" \
          -H "X-Target-Service: service_executer" \
          -H "X-Request-ID: req_$(date +%s)"
    fi
}

# Simulate different service calls
echo "1. Get service health:"
simulate_service_call "/admin/system/health" "GET"

echo -e "\n2. Create user:"
simulate_service_call "/users" "POST" '{
  "username": "serviceuser_'$(date +%s)'",
  "email": "serviceuser@example.com",
  "password": "ServicePass123!",
  "first_name": "Service",
  "last_name": "User"
}'

echo -e "\n3. Get user statistics:"
simulate_service_call "/users/stats/overview" "GET"
```

## 🔒 Step 5: Security Headers and Best Practices

### Enhanced Request Headers

```bash
# service_brain implements security best practices
echo "=== Enhanced Security Headers ==="

make_secure_request() {
    local endpoint=$1
    local method=${2:-GET}
    local data=$3
    
    # Generate request ID for tracing
    local request_id="brain_$(date +%s)_$$"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    echo "Making secure request to: $endpoint"
    echo "Request ID: $request_id"
    
    local curl_cmd="curl -k -s -w \"\nHTTP_STATUS:%{http_code}\nRESPONSE_TIME:%{time_total}\" \
      -X \"$method\" \"${BASE_URL}${API_BASE}${endpoint}\" \
      -H \"Authorization: Bearer ${BRAIN_TOKEN}\" \
      -H \"Content-Type: application/json\" \
      -H \"Accept: application/json\" \
      -H \"User-Agent: service_brain/1.0\" \
      -H \"X-Service-Name: service_brain\" \
      -H \"X-Service-Version: 1.0.0\" \
      -H \"X-Request-ID: $request_id\" \
      -H \"X-Request-Timestamp: $timestamp\" \
      -H \"X-Target-Service: service_executer\""
    
    if [ -n "$data" ]; then
        curl_cmd="$curl_cmd -d '$data'"
    fi
    
    eval "$curl_cmd"
}

# Test secure requests
make_secure_request "/users/me"
make_secure_request "/admin/dashboard/stats"
```

## 📊 Step 6: Request Monitoring and Logging

### Request Logging

```bash
# service_brain implements comprehensive logging
echo "=== Request Monitoring ==="

log_request() {
    local method=$1
    local endpoint=$2
    local status_code=$3
    local response_time=$4
    local request_id=$5
    
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    echo "[$timestamp] service_brain REQUEST_LOG: {
      \"request_id\": \"$request_id\",
      \"method\": \"$method\",
      \"endpoint\": \"$endpoint\",
      \"status_code\": $status_code,
      \"response_time\": $response_time,
      \"service\": \"service_brain\",
      \"target_service\": \"service_executer\"
    }"
}

# Make monitored request
monitored_request() {
    local endpoint=$1
    local method=${2:-GET}
    local request_id="brain_$(date +%s)_$$"
    
    local response=$(curl -k -s -w "\n%{http_code}\n%{time_total}" \
      -X "$method" "${BASE_URL}${API_BASE}${endpoint}" \
      -H "Authorization: Bearer ${BRAIN_TOKEN}" \
      -H "X-Request-ID: $request_id")
    
    local body=$(echo "$response" | head -n -2)
    local status_code=$(echo "$response" | tail -n 2 | head -n 1)
    local response_time=$(echo "$response" | tail -n 1)
    
    # Log the request
    log_request "$method" "$endpoint" "$status_code" "$response_time" "$request_id"
    
    # Return response body
    echo "$body"
}

# Test monitored requests
echo "Making monitored requests:"
monitored_request "/users/me"
monitored_request "/admin/system/health"
```

## 🧪 Step 7: Error Handling

### Comprehensive Error Handling

```bash
# service_brain implements robust error handling
echo "=== Error Handling Tests ==="

handle_api_error() {
    local response=$1
    local status_code=$2
    
    case $status_code in
        200|201|204)
            echo "✅ Success: $response"
            return 0
            ;;
        401)
            echo "❌ Unauthorized: Token may be expired or invalid"
            echo "Response: $response"
            # Trigger token refresh
            echo "Attempting token refresh..."
            BRAIN_TOKEN=$(refresh_service_token)
            return 1
            ;;
        403)
            echo "❌ Forbidden: Insufficient scopes or permissions"
            echo "Response: $response"
            return 1
            ;;
        404)
            echo "❌ Not Found: Endpoint or resource doesn't exist"
            echo "Response: $response"
            return 1
            ;;
        429)
            echo "❌ Rate Limited: Too many requests"
            local retry_after=$(echo "$response" | jq -r '.retry_after // 60')
            echo "Retry after: $retry_after seconds"
            return 1
            ;;
        500|502|503)
            echo "❌ Server Error: service_executer may be down"
            echo "Response: $response"
            return 1
            ;;
        *)
            echo "❌ Unknown Error ($status_code): $response"
            return 1
            ;;
    esac
}

# Test error scenarios
test_error_scenario() {
    local scenario=$1
    local endpoint=$2
    local token=$3
    
    echo "Testing scenario: $scenario"
    
    local response=$(curl -k -s -w "\n%{http_code}" \
      -X GET "${BASE_URL}${API_BASE}${endpoint}" \
      -H "Authorization: Bearer ${token}")
    
    local body=$(echo "$response" | head -n -1)
    local status_code=$(echo "$response" | tail -n 1)
    
    handle_api_error "$body" "$status_code"
}

# Test different error scenarios
test_error_scenario "Valid token" "/users/me" "$BRAIN_TOKEN"
test_error_scenario "Invalid token" "/users/me" "invalid_token_here"
test_error_scenario "Non-existent endpoint" "/nonexistent" "$BRAIN_TOKEN"
```

## 📋 Step 8: Complete Service Brain Implementation

### Python Implementation Example

```python
#!/usr/bin/env python3
"""
service_brain - Initiator Service Implementation
"""

import requests
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

class ServiceBrain:
    """service_brain implementation for service-to-service communication."""
    
    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url.rstrip('/')
        self.api_base = "/api/v1"
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.token_expires_at = None
        
        # Configure session
        self.session = requests.Session()
        self.session.verify = False  # For testing with self-signed certs
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'service_brain/1.0',
            'X-Service-Name': 'service_brain'
        })
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger('service_brain')
    
    def authenticate(self) -> bool:
        """Authenticate with Permiso and get access token."""
        try:
            url = f"{self.base_url}{self.api_base}/auth/service-token"
            data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'client_credentials',
                'scope': 'api:read api:write service:communicate'
            }
            
            response = self.session.post(
                url, 
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.access_token = token_data['access_token']
                expires_in = token_data.get('expires_in', 3600)
                self.token_expires_at = datetime.now() + timedelta(seconds=expires_in - 60)
                
                # Update session headers
                self.session.headers['Authorization'] = f"Bearer {self.access_token}"
                
                self.logger.info("service_brain authenticated successfully")
                return True
            else:
                self.logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False
    
    def ensure_authenticated(self) -> bool:
        """Ensure we have a valid access token."""
        if not self.access_token or (self.token_expires_at and datetime.now() >= self.token_expires_at):
            return self.authenticate()
        return True
    
    def call_service_executer(self, endpoint: str, method: str = 'GET', data: Dict = None) -> Optional[Dict]:
        """Make authenticated request to service_executer."""
        if not self.ensure_authenticated():
            self.logger.error("Failed to authenticate")
            return None
        
        try:
            url = f"{self.base_url}{self.api_base}{endpoint}"
            request_id = f"brain_{int(time.time())}_{id(self)}"
            
            headers = {
                'X-Request-ID': request_id,
                'X-Target-Service': 'service_executer',
                'X-Request-Timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            self.logger.info(f"service_brain calling service_executer: {method} {endpoint}")
            
            response = self.session.request(method, url, json=data, headers=headers)
            
            self.logger.info(f"Response: {response.status_code} in {response.elapsed.total_seconds():.3f}s")
            
            if response.status_code in [200, 201, 204]:
                return response.json() if response.content else {}
            else:
                self.logger.error(f"Request failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            self.logger.error(f"Request error: {e}")
            return None

# Usage example
if __name__ == "__main__":
    brain = ServiceBrain(
        base_url="https://localhost:443",
        client_id="service-brain-001",
        client_secret="your-brain-secret"
    )
    
    if brain.authenticate():
        # Test service calls
        result = brain.call_service_executer("/users/me")
        print(f"User profile: {result}")
        
        result = brain.call_service_executer("/admin/system/health")
        print(f"System health: {result}")
```

This completes the service_brain implementation with comprehensive authentication, request handling, error management, and monitoring capabilities.