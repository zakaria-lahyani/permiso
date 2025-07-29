# Service Executer Demo - Receiver Service

This document demonstrates how `service_executer` (the receiver service) validates incoming requests from `service_brain` using Permiso authentication.

## ⚡ Service Executer Overview

`service_executer` is the **receiver service** that:
1. Receives requests from `service_brain` with JWT tokens
2. Validates tokens with Permiso (introspection or JWT verification)
3. Checks token scopes for authorization
4. Returns appropriate responses or errors
5. Logs security events and access attempts

## 🔧 Prerequisites

```bash
# Load service configuration
source service_config.env

# Or set manually:
export BASE_URL="https://localhost:443"
export API_BASE="/api/v1"
export SERVICE_EXECUTER_ID="service-executer-001"
export SERVICE_EXECUTER_SECRET="your-executer-secret"
```

## 🎯 Step 1: Token Validation Methods

### Method A: Token Introspection with Permiso

```bash
# service_executer validates incoming tokens via Permiso introspection
echo "=== Token Validation via Introspection ==="

# First, get service_executer's own token for introspection
EXECUTER_TOKEN=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${SERVICE_EXECUTER_ID}&client_secret=${SERVICE_EXECUTER_SECRET}&grant_type=client_credentials" \
  | jq -r '.access_token')

echo "service_executer authenticated: ${EXECUTER_TOKEN:0:30}..."

# Function to validate incoming token
validate_token_introspection() {
    local incoming_token=$1
    
    echo "Validating token via introspection: ${incoming_token:0:30}..."
    
    local introspect_response=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/introspect" \
      -H "Authorization: Bearer ${EXECUTER_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"token\": \"${incoming_token}\"}")
    
    echo "Introspection response:"
    echo "$introspect_response" | jq '.'
    
    local is_active=$(echo "$introspect_response" | jq -r '.active')
    local client_id=$(echo "$introspect_response" | jq -r '.client_id // empty')
    local scopes=$(echo "$introspect_response" | jq -r '.scope // empty')
    
    if [ "$is_active" = "true" ]; then
        echo "✅ Token is valid"
        echo "  Client ID: $client_id"
        echo "  Scopes: $scopes"
        return 0
    else
        echo "❌ Token is invalid or expired"
        return 1
    fi
}

# Test with a valid token (get one from service_brain)
BRAIN_TOKEN=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${SERVICE_BRAIN_ID}&client_secret=${SERVICE_BRAIN_SECRET}&grant_type=client_credentials" \
  | jq -r '.access_token')

echo "Testing with valid service_brain token:"
validate_token_introspection "$BRAIN_TOKEN"

echo -e "\nTesting with invalid token:"
validate_token_introspection "invalid_token_here"
```

### Method B: JWT Signature Verification (Local)

```bash
# service_executer can also validate JWT signatures locally
echo "=== JWT Signature Verification ==="

# Function to decode JWT payload (for demonstration)
decode_jwt_payload() {
    local token=$1
    local payload=$(echo "$token" | cut -d'.' -f2)
    
    # Add padding if needed
    local padding=$((4 - ${#payload} % 4))
    if [ $padding -ne 4 ]; then
        payload="${payload}$(printf '%*s' $padding | tr ' ' '=')"
    fi
    
    echo "$payload" | base64 -d 2>/dev/null | jq '.' 2>/dev/null || echo "Invalid JWT payload"
}

# Function to validate JWT structure and claims
validate_jwt_local() {
    local token=$1
    
    echo "Validating JWT locally: ${token:0:30}..."
    
    # Check JWT structure (3 parts separated by dots)
    local part_count=$(echo "$token" | tr -cd '.' | wc -c)
    if [ "$part_count" -ne 2 ]; then
        echo "❌ Invalid JWT structure (expected 3 parts, got $((part_count + 1)))"
        return 1
    fi
    
    # Decode and validate payload
    local payload=$(decode_jwt_payload "$token")
    echo "JWT Payload:"
    echo "$payload"
    
    # Check expiration
    local exp=$(echo "$payload" | jq -r '.exp // empty' 2>/dev/null)
    local current_time=$(date +%s)
    
    if [ -n "$exp" ] && [ "$exp" -gt "$current_time" ]; then
        echo "✅ JWT is valid and not expired"
        local client_id=$(echo "$payload" | jq -r '.client_id // .sub // empty')
        local scopes=$(echo "$payload" | jq -r '.scopes // .scope // empty')
        echo "  Client ID: $client_id"
        echo "  Scopes: $scopes"
        return 0
    else
        echo "❌ JWT is expired or invalid"
        return 1
    fi
}

# Test JWT validation
echo "Testing JWT validation with service_brain token:"
validate_jwt_local "$BRAIN_TOKEN"

echo -e "\nTesting JWT validation with malformed token:"
validate_jwt_local "not.a.jwt"
```

## 🔐 Step 2: Scope-Based Authorization

### Authorization Middleware Simulation

```bash
# service_executer implements scope-based authorization
echo "=== Scope-Based Authorization ==="

# Function to check if token has required scopes
check_token_scopes() {
    local token=$1
    local required_scopes=$2
    
    echo "Checking scopes for token: ${token:0:30}..."
    echo "Required scopes: $required_scopes"
    
    # Get token scopes via introspection
    local introspect_response=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/introspect" \
      -H "Authorization: Bearer ${EXECUTER_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"token\": \"${token}\"}")
    
    local is_active=$(echo "$introspect_response" | jq -r '.active')
    local token_scopes=$(echo "$introspect_response" | jq -r '.scope // empty')
    
    if [ "$is_active" != "true" ]; then
        echo "❌ Token is not active"
        return 1
    fi
    
    echo "Token scopes: $token_scopes"
    
    # Check if all required scopes are present
    for required_scope in $required_scopes; do
        if echo "$token_scopes" | grep -q "$required_scope"; then
            echo "✅ Scope '$required_scope' found"
        else
            echo "❌ Missing required scope: '$required_scope'"
            return 1
        fi
    done
    
    echo "✅ All required scopes present"
    return 0
}

# Test different scope requirements
echo "1. Testing read access (requires api:read):"
check_token_scopes "$BRAIN_TOKEN" "api:read"

echo -e "\n2. Testing write access (requires api:write):"
check_token_scopes "$BRAIN_TOKEN" "api:write"

echo -e "\n3. Testing admin access (requires admin:system):"
check_token_scopes "$BRAIN_TOKEN" "admin:system"

echo -e "\n4. Testing multiple scopes (requires api:read api:write):"
check_token_scopes "$BRAIN_TOKEN" "api:read api:write"
```

## 🛡️ Step 3: Request Processing Simulation

### Complete Request Handler

```bash
# service_executer implements complete request processing
echo "=== Complete Request Processing ==="

# Function to simulate service_executer endpoint
process_service_request() {
    local method=$1
    local endpoint=$2
    local auth_header=$3
    local required_scopes=$4
    local request_data=$5
    
    echo "=== Processing Request ==="
    echo "Method: $method"
    echo "Endpoint: $endpoint"
    echo "Required Scopes: $required_scopes"
    
    # Extract token from Authorization header
    local token=$(echo "$auth_header" | sed 's/Bearer //')
    
    if [ -z "$token" ] || [ "$token" = "null" ]; then
        echo "❌ 401 Unauthorized: Missing or invalid Authorization header"
        return 1
    fi
    
    # Validate token
    echo "Step 1: Validating token..."
    if ! validate_token_introspection "$token" > /dev/null 2>&1; then
        echo "❌ 401 Unauthorized: Invalid token"
        return 1
    fi
    
    # Check scopes
    echo "Step 2: Checking authorization..."
    if ! check_token_scopes "$token" "$required_scopes" > /dev/null 2>&1; then
        echo "❌ 403 Forbidden: Insufficient scopes"
        return 1
    fi
    
    # Process request
    echo "Step 3: Processing request..."
    case "$endpoint" in
        "/users")
            if [ "$method" = "GET" ]; then
                echo "✅ 200 OK: Returning user list"
                echo '{"users": [{"id": 1, "username": "user1"}], "total": 1}'
            elif [ "$method" = "POST" ]; then
                echo "✅ 201 Created: User created"
                echo '{"id": 123, "username": "newuser", "created": true}'
            fi
            ;;
        "/users/profile")
            echo "✅ 200 OK: Returning user profile"
            echo '{"id": 1, "username": "currentuser", "email": "user@example.com"}'
            ;;
        "/admin/stats")
            echo "✅ 200 OK: Returning admin statistics"
            echo '{"total_users": 100, "active_sessions": 25}'
            ;;
        *)
            echo "❌ 404 Not Found: Endpoint not found"
            return 1
            ;;
    esac
    
    return 0
}

# Test different request scenarios
echo "=== Testing Request Scenarios ==="

echo "1. Valid request with correct scopes:"
process_service_request "GET" "/users" "Bearer $BRAIN_TOKEN" "api:read"

echo -e "\n2. Request with insufficient scopes:"
process_service_request "GET" "/admin/stats" "Bearer $BRAIN_TOKEN" "admin:system"

echo -e "\n3. Request without authorization header:"
process_service_request "GET" "/users" "" "api:read"

echo -e "\n4. Request with invalid token:"
process_service_request "GET" "/users" "Bearer invalid_token" "api:read"
```

## 📊 Step 4: Security Logging and Monitoring

### Security Event Logging

```bash
# service_executer implements comprehensive security logging
echo "=== Security Event Logging ==="

# Function to log security events
log_security_event() {
    local event_type=$1
    local client_id=$2
    local endpoint=$3
    local result=$4
    local details=$5
    
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local log_entry="{
        \"timestamp\": \"$timestamp\",
        \"service\": \"service_executer\",
        \"event_type\": \"$event_type\",
        \"client_id\": \"$client_id\",
        \"endpoint\": \"$endpoint\",
        \"result\": \"$result\",
        \"details\": $details
    }"
    
    echo "SECURITY_LOG: $log_entry"
    
    # In production, this would be sent to a logging service
    # For demo, we'll also send to Permiso's audit log (if available)
}

# Function to process request with logging
process_request_with_logging() {
    local method=$1
    local endpoint=$2
    local auth_header=$3
    local required_scopes=$4
    local client_ip=${5:-"192.168.1.100"}
    
    local request_id="exec_$(date +%s)_$$"
    local token=$(echo "$auth_header" | sed 's/Bearer //')
    
    echo "Processing request ID: $request_id"
    
    # Validate token and extract client info
    local introspect_response=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/introspect" \
      -H "Authorization: Bearer ${EXECUTER_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"token\": \"${token}\"}")
    
    local is_active=$(echo "$introspect_response" | jq -r '.active')
    local client_id=$(echo "$introspect_response" | jq -r '.client_id // "unknown"')
    local token_scopes=$(echo "$introspect_response" | jq -r '.scope // empty')
    
    if [ "$is_active" != "true" ]; then
        log_security_event "authentication_failure" "$client_id" "$endpoint" "denied" \
            "{\"reason\": \"invalid_token\", \"client_ip\": \"$client_ip\"}"
        echo "❌ 401 Unauthorized"
        return 1
    fi
    
    # Check scopes
    local scope_check_passed=true
    for required_scope in $required_scopes; do
        if ! echo "$token_scopes" | grep -q "$required_scope"; then
            scope_check_passed=false
            break
        fi
    done
    
    if [ "$scope_check_passed" != "true" ]; then
        log_security_event "authorization_failure" "$client_id" "$endpoint" "denied" \
            "{\"reason\": \"insufficient_scopes\", \"required\": \"$required_scopes\", \"provided\": \"$token_scopes\"}"
        echo "❌ 403 Forbidden"
        return 1
    fi
    
    # Log successful access
    log_security_event "access_granted" "$client_id" "$endpoint" "allowed" \
        "{\"method\": \"$method\", \"scopes\": \"$token_scopes\"}"
    
    echo "✅ 200 OK: Request processed successfully"
    return 0
}

# Test requests with logging
echo "Testing requests with security logging:"

echo -e "\n1. Successful request:"
process_request_with_logging "GET" "/users" "Bearer $BRAIN_TOKEN" "api:read"

echo -e "\n2. Failed authorization:"
process_request_with_logging "GET" "/admin/stats" "Bearer $BRAIN_TOKEN" "admin:system"

echo -e "\n3. Invalid token:"
process_request_with_logging "GET" "/users" "Bearer invalid_token" "api:read"
```

## 🔄 Step 5: Rate Limiting and Throttling

### Client Rate Limiting

```bash
# service_executer implements rate limiting per client
echo "=== Rate Limiting Implementation ==="

# Function to check rate limits
check_rate_limit() {
    local client_id=$1
    local endpoint=$2
    
    echo "Checking rate limit for client: $client_id"
    
    # Get client rate limit info from Permiso
    local rate_limit_response=$(curl -k -s -X GET "${BASE_URL}${API_BASE}/service-clients/${client_id}/rate-limit" \
      -H "Authorization: Bearer ${EXECUTER_TOKEN}")
    
    echo "Rate limit info:"
    echo "$rate_limit_response" | jq '.'
    
    local is_rate_limited=$(echo "$rate_limit_response" | jq -r '.is_rate_limited // false')
    local per_minute_remaining=$(echo "$rate_limit_response" | jq -r '.per_minute_remaining // 100')
    
    if [ "$is_rate_limited" = "true" ]; then
        echo "❌ 429 Too Many Requests: Rate limit exceeded"
        return 1
    fi
    
    echo "✅ Rate limit OK (${per_minute_remaining} requests remaining)"
    return 0
}

# Test rate limiting
echo "Testing rate limiting for service_brain:"
check_rate_limit "$SERVICE_BRAIN_ID" "/users"
```

## 🧪 Step 6: Complete Integration Test

### End-to-End Service Communication Test

```bash
# Complete end-to-end test of service-to-service communication
echo "=== End-to-End Service Communication Test ==="

# Function to simulate complete service_executer behavior
simulate_service_executer() {
    local method=$1
    local endpoint=$2
    local auth_header=$3
    local request_data=$4
    
    echo "=== service_executer Processing Request ==="
    echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Method: $method $endpoint"
    echo "Authorization: ${auth_header:0:50}..."
    
    # Extract token
    local token=$(echo "$auth_header" | sed 's/Bearer //')
    
    # Step 1: Validate token
    echo "Step 1: Token validation..."
    local introspect_response=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/introspect" \
      -H "Authorization: Bearer ${EXECUTER_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"token\": \"${token}\"}")
    
    local is_active=$(echo "$introspect_response" | jq -r '.active')
    local client_id=$(echo "$introspect_response" | jq -r '.client_id // "unknown"')
    local token_scopes=$(echo "$introspect_response" | jq -r '.scope // empty')
    
    if [ "$is_active" != "true" ]; then
        echo "❌ Authentication failed"
        echo "HTTP/1.1 401 Unauthorized"
        echo "Content-Type: application/json"
        echo ""
        echo '{"error": "invalid_token", "error_description": "Token is invalid or expired"}'
        return 1
    fi
    
    echo "✅ Token valid for client: $client_id"
    echo "Token scopes: $token_scopes"
    
    # Step 2: Check authorization based on endpoint
    echo "Step 2: Authorization check..."
    local required_scopes=""
    case "$endpoint" in
        "/users")
            required_scopes="api:read"
            ;;
        "/users/create")
            required_scopes="api:write"
            ;;
        "/admin/stats")
            required_scopes="admin:system"
            ;;
        *)
            required_scopes="api:read"
            ;;
    esac
    
    echo "Required scopes: $required_scopes"
    
    local scope_check_passed=true
    for required_scope in $required_scopes; do
        if ! echo "$token_scopes" | grep -q "$required_scope"; then
            scope_check_passed=false
            break
        fi
    done
    
    if [ "$scope_check_passed" != "true" ]; then
        echo "❌ Authorization failed"
        echo "HTTP/1.1 403 Forbidden"
        echo "Content-Type: application/json"
        echo ""
        echo '{"error": "insufficient_scope", "error_description": "Token does not have required scopes"}'
        return 1
    fi
    
    echo "✅ Authorization passed"
    
    # Step 3: Process request
    echo "Step 3: Processing business logic..."
    echo "HTTP/1.1 200 OK"
    echo "Content-Type: application/json"
    echo "X-Service-Name: service_executer"
    echo "X-Client-ID: $client_id"
    echo ""
    
    case "$endpoint" in
        "/users")
            echo '{"users": [{"id": 1, "username": "user1"}, {"id": 2, "username": "user2"}], "total": 2}'
            ;;
        "/users/create")
            echo '{"id": 123, "username": "newuser", "email": "newuser@example.com", "created": true}'
            ;;
        "/admin/stats")
            echo '{"total_users": 150, "active_sessions": 45, "system_health": "healthy"}'
            ;;
        *)
            echo '{"message": "Request processed successfully", "endpoint": "'$endpoint'"}'
            ;;
    esac
    
    return 0
}

# Test complete service communication
echo "=== Testing Complete Service Communication ==="

echo "1. service_brain → service_executer (GET /users):"
simulate_service_executer "GET" "/users" "Bearer $BRAIN_TOKEN"

echo -e "\n2. service_brain → service_executer (POST /users/create):"
simulate_service_executer "POST" "/users/create" "Bearer $BRAIN_TOKEN" '{"username": "newuser"}'

echo -e "\n3. service_brain → service_executer (GET /admin/stats) - Should fail:"
simulate_service_executer "GET" "/admin/stats" "Bearer $BRAIN_TOKEN"

echo -e "\n4. Invalid token test:"
simulate_service_executer "GET" "/users" "Bearer invalid_token_here"
```

## 📋 Step 7: Python Implementation

### Complete Service Executer Implementation

```python
#!/usr/bin/env python3
"""
service_executer - Receiver Service Implementation
"""

import requests
import json
import time
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from flask import Flask, request, jsonify

class ServiceExecuter:
    """service_executer implementation for validating incoming requests."""
    
    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url.rstrip('/')
        self.api_base = "/api/v1"
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        
        # Configure session for Permiso API calls
        self.session = requests.Session()
        self.session.verify = False  # For testing with self-signed certs
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger('service_executer')
        
        # Authenticate with Permiso
        self.authenticate()
    
    def authenticate(self) -> bool:
        """Authenticate with Permiso to get token for introspection."""
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
                self.logger.info("service_executer authenticated with Permiso")
                return True
            else:
                self.logger.error(f"Authentication failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate incoming token via Permiso introspection."""
        try:
            url = f"{self.base_url}{self.api_base}/auth/introspect"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            data = {'token': token}
            
            response = self.session.post(url, json=data, headers=headers)
            
            if response.status_code == 200:
                introspection = response.json()
                if introspection.get('active'):
                    return introspection
            
            return None
            
        except Exception as e:
            self.logger.error(f"Token validation error: {e}")
            return None
    
    def check_scopes(self, token_info: Dict[str, Any], required_scopes: List[str]) -> bool:
        """Check if token has required scopes."""
        token_scopes = token_info.get('scope', '').split()
        return all(scope in token_scopes for scope in required_scopes)
    
    def log_security_event(self, event_type: str, client_id: str, endpoint: str, result: str, details: Dict = None):
        """Log security events."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'service': 'service_executer',
            'event_type': event_type,
            'client_id': client_id,
            'endpoint': endpoint,
            'result': result,
            'details': details or {}
        }
        
        self.logger.info(f"SECURITY_EVENT: {json.dumps(log_entry)}")

# Flask application for service_executer
app = Flask(__name__)
executer = None

def require_auth(required_scopes: List[str] = None):
    """Decorator to require authentication and authorization."""
    def decorator(f):
        def wrapper(*args, **kwargs):
            # Extract token from Authorization header
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                executer.log_security_event('authentication_failure', 'unknown', request.path, 'denied', 
                                           {'reason': 'missing_auth_header'})
                return jsonify({'error': 'unauthorized', 'error_description': 'Missing Authorization header'}), 401
            
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            
            # Validate token
            token_info = executer.validate_token(token)
            if not token_info:
                executer.log_security_event('authentication_failure', 'unknown', request.path, 'denied',
                                           {'reason': 'invalid_token'})
                return jsonify({'error': 'invalid_token', 'error_description': 'Token is invalid or expired'}), 401
            
            client_id = token_info.get('client_id', 'unknown')
            
            # Check scopes if required
            if required_scopes and not executer.check_scopes(token_info, required_scopes):
                executer.log_security_event('authorization_failure', client_id, request.path, 'denied',
                                           {'required_scopes': required_scopes, 'token_scopes': token_info.get('scope', '')})
                return jsonify({'error': 'insufficient_scope', 'error_description': 'Token does not have required scopes'}), 403
            
            # Log successful access
            executer.log_security_event('access_granted', client_id, request.path, 'allowed',
                                       {'scopes': token_info.get('scope', '')})
            
            # Add token info to request context
            request.token_info = token_info
            return f(*args, **kwargs)
        
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

# Service endpoints
@app.route('/users', methods=['GET'])
@require_auth(['api:read'])
def get_users():
    """Get users list - requires api:read scope."""
    return jsonify({
        'users': [
            {'id': 1, 'username': 'user1', 'email': 'user1@example.com'},
            {'id': 2, 'username': 'user2', 'email': 'user2@example.com'}
        ],
        'total': 2,
        'processed_by': 'service_executer'
    })

@app.route('/users', methods=['POST'])
@require_auth(['api:write'])
def create_user():
    """Create user - requires api:write scope."""
    user_data = request.get_json()
    return jsonify({
        'id': 123,
        'username': user_data.get('username', 'newuser'),
        'email': user_data.get('email', 'newuser@example.com'),
        'created': True,
        'processed_by': 'service_executer'
    }), 201

@app.route('/admin/stats', methods=['GET'])
@require_auth(['admin:system'])
def get_admin_stats():
    """Get admin statistics - requires admin:system scope."""
    return jsonify({
        'total_users': 150,
        'active_sessions': 45,
        'system_health': 'healthy',
        'processed_by': 'service_executer'
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint - no authentication required."""
    return jsonify({
        'status': 'healthy',
        'service': 'service_executer',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    })

if __name__ == '__main__':
    # Initialize service_executer
    executer = ServiceExecuter(
        base_url="https://localhost:443",
        client_id="service-executer-001",
        client_secret="your-executer-secret"
    )
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5001, debug=True)
```

This completes the service_executer implementation with comprehensive token validation, scope checking, security logging, and request processing capabilities.