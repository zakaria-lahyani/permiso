# Service-to-Service Error Handling Guide

This document provides comprehensive error handling patterns for service-to-service authentication and communication with the Permiso API.

## 🚨 Error Categories

### 1. Authentication Errors (4xx)
- **401 Unauthorized** - Invalid or missing credentials
- **403 Forbidden** - Valid credentials but insufficient permissions
- **422 Unprocessable Entity** - Invalid request format

### 2. Client Errors (4xx)
- **400 Bad Request** - Malformed request
- **404 Not Found** - Resource doesn't exist
- **409 Conflict** - Resource conflict
- **429 Too Many Requests** - Rate limiting

### 3. Server Errors (5xx)
- **500 Internal Server Error** - Server-side issues
- **502 Bad Gateway** - Upstream service issues
- **503 Service Unavailable** - Service temporarily down

## 🔐 Authentication Error Handling

### Error: `invalid_client`

**Scenario**: Invalid `client_id` or `client_secret`

```bash
# Example request that triggers invalid_client
curl -k -s -X POST "${BASE_URL}/api/v1/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=invalid-client&client_secret=wrong-secret&grant_type=client_credentials"

# Response (HTTP 401)
{
  "error": "invalid_client",
  "error_description": "Client authentication failed",
  "error_code": "AUTH_001"
}
```

**Handling Strategy**:
```bash
handle_invalid_client() {
    local response=$1
    local error=$(echo "$response" | jq -r '.error // "unknown"')
    
    if [ "$error" = "invalid_client" ]; then
        echo "❌ ERROR: Invalid client credentials"
        echo "Action: Verify client_id and client_secret in configuration"
        echo "Check: Service registration in Permiso admin panel"
        
        # Log security event
        log_security_event "INVALID_CLIENT_ATTEMPT" "$(date)" "$CLIENT_ID"
        
        return 1
    fi
    
    return 0
}
```

### Error: `unauthorized_scope`

**Scenario**: Requesting scopes not granted to the service

```bash
# Request with unauthorized scope
curl -k -s -X POST "${BASE_URL}/api/v1/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${SERVICE_BRAIN_ID}&client_secret=${SERVICE_BRAIN_SECRET}&grant_type=client_credentials&scope=admin:system"

# Response (HTTP 400)
{
  "error": "invalid_scope",
  "error_description": "Requested scope exceeds granted permissions",
  "error_code": "AUTH_002",
  "requested_scope": "admin:system",
  "granted_scopes": ["api:read", "api:write"]
}
```

**Handling Strategy**:
```bash
handle_unauthorized_scope() {
    local response=$1
    local error=$(echo "$response" | jq -r '.error // "unknown"')
    
    if [ "$error" = "invalid_scope" ]; then
        local requested=$(echo "$response" | jq -r '.requested_scope // "unknown"')
        local granted=$(echo "$response" | jq -r '.granted_scopes // []')
        
        echo "❌ ERROR: Unauthorized scope requested"
        echo "Requested: $requested"
        echo "Granted: $granted"
        echo "Action: Request scope elevation from admin or modify request"
        
        # Fallback to basic scopes
        echo "Attempting fallback authentication with basic scopes..."
        fallback_token=$(get_service_token_basic_scopes)
        
        if [ -n "$fallback_token" ]; then
            echo "✅ Fallback authentication successful"
            return 0
        fi
        
        return 1
    fi
    
    return 0
}

get_service_token_basic_scopes() {
    curl -k -s -X POST "${BASE_URL}/api/v1/auth/service-token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "client_id=${SERVICE_BRAIN_ID}&client_secret=${SERVICE_BRAIN_SECRET}&grant_type=client_credentials&scope=api:read" \
      | jq -r '.access_token // empty'
}
```

### Error: `token_expired`

**Scenario**: Using an expired access token

```bash
# Using expired token
curl -k -s -X GET "${BASE_URL}/api/v1/users/me" \
  -H "Authorization: Bearer ${EXPIRED_TOKEN}"

# Response (HTTP 401)
{
  "error": "token_expired",
  "error_description": "The access token has expired",
  "error_code": "AUTH_003",
  "expired_at": "2024-01-15T10:30:00Z"
}
```

**Handling Strategy**:
```bash
handle_token_expired() {
    local response=$1
    local http_status=$2
    
    if [ "$http_status" = "401" ]; then
        local error=$(echo "$response" | jq -r '.error // "unknown"')
        
        if [ "$error" = "token_expired" ]; then
            echo "⚠️  WARNING: Token expired, attempting refresh..."
            
            # Attempt token refresh
            local new_token=$(refresh_service_token)
            
            if [ -n "$new_token" ]; then
                echo "✅ Token refreshed successfully"
                export CURRENT_TOKEN="$new_token"
                return 0
            else
                echo "❌ ERROR: Token refresh failed"
                return 1
            fi
        fi
    fi
    
    return 0
}

refresh_service_token() {
    local new_token=$(curl -k -s -X POST "${BASE_URL}/api/v1/auth/service-token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "client_id=${SERVICE_BRAIN_ID}&client_secret=${SERVICE_BRAIN_SECRET}&grant_type=client_credentials" \
      | jq -r '.access_token // empty')
    
    if [ -n "$new_token" ] && [ "$new_token" != "null" ]; then
        echo "$new_token"
    fi
}
```

## 🔒 Authorization Error Handling

### Error: `insufficient_scope`

**Scenario**: Valid token but insufficient permissions for the requested resource

```bash
# Request requiring admin scope with basic token
curl -k -s -X GET "${BASE_URL}/api/v1/admin/system/health" \
  -H "Authorization: Bearer ${BASIC_TOKEN}"

# Response (HTTP 403)
{
  "error": "insufficient_scope",
  "error_description": "Token does not have required scope for this resource",
  "error_code": "AUTHZ_001",
  "required_scope": "admin:system",
  "token_scopes": ["api:read", "api:write"]
}
```

**Handling Strategy**:
```bash
handle_insufficient_scope() {
    local response=$1
    local http_status=$2
    
    if [ "$http_status" = "403" ]; then
        local error=$(echo "$response" | jq -r '.error // "unknown"')
        
        if [ "$error" = "insufficient_scope" ]; then
            local required=$(echo "$response" | jq -r '.required_scope // "unknown"')
            local current=$(echo "$response" | jq -r '.token_scopes // []')
            
            echo "❌ ERROR: Insufficient scope for operation"
            echo "Required: $required"
            echo "Current: $current"
            
            # Check if we can request elevated token
            if can_request_elevated_scope "$required"; then
                echo "Attempting to request elevated token..."
                local elevated_token=$(request_elevated_token "$required")
                
                if [ -n "$elevated_token" ]; then
                    echo "✅ Elevated token obtained"
                    export CURRENT_TOKEN="$elevated_token"
                    return 0
                fi
            fi
            
            echo "Action: Contact administrator for scope elevation"
            return 1
        fi
    fi
    
    return 0
}

can_request_elevated_scope() {
    local required_scope=$1
    
    # Check if service is configured for scope elevation
    case "$required_scope" in
        "admin:system"|"admin:users")
            # Only specific services can request admin scopes
            if [ "$SERVICE_NAME" = "service_brain" ] && [ "$ALLOW_ELEVATION" = "true" ]; then
                return 0
            fi
            ;;
        "api:write"|"api:read")
            # Most services can request basic API scopes
            return 0
            ;;
    esac
    
    return 1
}

request_elevated_token() {
    local scope=$1
    
    curl -k -s -X POST "${BASE_URL}/api/v1/auth/service-token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "client_id=${SERVICE_BRAIN_ID}&client_secret=${SERVICE_BRAIN_SECRET}&grant_type=client_credentials&scope=${scope}" \
      | jq -r '.access_token // empty'
}
```

## 🌐 Network and Service Error Handling

### Error: Connection Failures

```bash
handle_connection_error() {
    local exit_code=$1
    local url=$2
    
    case $exit_code in
        6)  # Couldn't resolve host
            echo "❌ ERROR: Cannot resolve host"
            echo "Action: Check DNS configuration and network connectivity"
            ;;
        7)  # Failed to connect
            echo "❌ ERROR: Connection failed"
            echo "Action: Check if Permiso service is running and accessible"
            ;;
        28) # Operation timeout
            echo "❌ ERROR: Request timeout"
            echo "Action: Check network latency and service responsiveness"
            ;;
        35) # SSL connect error
            echo "❌ ERROR: SSL/TLS connection failed"
            echo "Action: Check certificate validity and SSL configuration"
            ;;
        *)
            echo "❌ ERROR: Unknown connection error (code: $exit_code)"
            ;;
    esac
    
    # Implement retry logic
    implement_retry_logic "$url"
}

implement_retry_logic() {
    local url=$1
    local max_retries=3
    local retry_delay=5
    
    for attempt in $(seq 1 $max_retries); do
        echo "Retry attempt $attempt/$max_retries in ${retry_delay}s..."
        sleep $retry_delay
        
        if curl -k -s --connect-timeout 10 --max-time 30 "$url" > /dev/null 2>&1; then
            echo "✅ Connection restored on attempt $attempt"
            return 0
        fi
        
        retry_delay=$((retry_delay * 2))  # Exponential backoff
    done
    
    echo "❌ All retry attempts failed"
    return 1
}
```

### Error: Rate Limiting (429)

```bash
handle_rate_limiting() {
    local response=$1
    local http_status=$2
    
    if [ "$http_status" = "429" ]; then
        local retry_after=$(echo "$response" | jq -r '.retry_after // 60')
        local limit=$(echo "$response" | jq -r '.rate_limit // "unknown"')
        
        echo "⚠️  WARNING: Rate limit exceeded"
        echo "Rate limit: $limit"
        echo "Retry after: ${retry_after}s"
        
        # Implement exponential backoff
        local wait_time=$retry_after
        echo "Waiting ${wait_time}s before retry..."
        sleep $wait_time
        
        return 0
    fi
    
    return 1
}
```

### Error: Server Errors (5xx)

```bash
handle_server_error() {
    local response=$1
    local http_status=$2
    
    case $http_status in
        500)
            echo "❌ ERROR: Internal server error"
            echo "Action: Check Permiso service logs and contact support"
            ;;
        502)
            echo "❌ ERROR: Bad gateway"
            echo "Action: Check upstream services and load balancer configuration"
            ;;
        503)
            echo "❌ ERROR: Service unavailable"
            echo "Action: Service may be temporarily down for maintenance"
            ;;
        504)
            echo "❌ ERROR: Gateway timeout"
            echo "Action: Check service responsiveness and timeout configurations"
            ;;
    esac
    
    # Log server error for monitoring
    log_server_error "$http_status" "$response"
    
    # Implement circuit breaker pattern
    increment_error_count
    
    if should_open_circuit; then
        echo "⚠️  Circuit breaker opened - stopping requests temporarily"
        return 1
    fi
    
    return 0
}

log_server_error() {
    local status=$1
    local response=$2
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    echo "[$timestamp] SERVER_ERROR: HTTP $status - $response" >> /var/log/service_errors.log
}

increment_error_count() {
    local error_file="/tmp/error_count_$$"
    local current_count=0
    
    if [ -f "$error_file" ]; then
        current_count=$(cat "$error_file")
    fi
    
    echo $((current_count + 1)) > "$error_file"
}

should_open_circuit() {
    local error_file="/tmp/error_count_$$"
    local threshold=5
    
    if [ -f "$error_file" ]; then
        local count=$(cat "$error_file")
        [ $count -ge $threshold ]
    else
        false
    fi
}
```

## 🔄 Comprehensive Error Handler

### Universal Error Handler Function

```bash
handle_api_response() {
    local response=$1
    local http_status=$2
    local request_context=$3
    
    echo "Processing response: HTTP $http_status"
    
    # Success responses
    if [[ $http_status =~ ^2[0-9][0-9]$ ]]; then
        echo "✅ Request successful"
        reset_error_count
        return 0
    fi
    
    # Client errors (4xx)
    if [[ $http_status =~ ^4[0-9][0-9]$ ]]; then
        case $http_status in
            400)
                handle_bad_request "$response" "$request_context"
                ;;
            401)
                handle_unauthorized "$response" "$request_context"
                ;;
            403)
                handle_forbidden "$response" "$request_context"
                ;;
            404)
                handle_not_found "$response" "$request_context"
                ;;
            409)
                handle_conflict "$response" "$request_context"
                ;;
            422)
                handle_unprocessable_entity "$response" "$request_context"
                ;;
            429)
                handle_rate_limiting "$response" "$http_status"
                return $?
                ;;
            *)
                echo "❌ Client error: HTTP $http_status"
                echo "Response: $response"
                ;;
        esac
        return 1
    fi
    
    # Server errors (5xx)
    if [[ $http_status =~ ^5[0-9][0-9]$ ]]; then
        handle_server_error "$response" "$http_status"
        return 1
    fi
    
    # Unknown status
    echo "❌ Unknown HTTP status: $http_status"
    echo "Response: $response"
    return 1
}

handle_bad_request() {
    local response=$1
    local context=$2
    
    echo "❌ ERROR: Bad request (400)"
    echo "Context: $context"
    
    local error_details=$(echo "$response" | jq -r '.error_description // .message // "No details available"')
    echo "Details: $error_details"
    
    # Check for common validation errors
    if echo "$response" | jq -e '.validation_errors' > /dev/null 2>&1; then
        echo "Validation errors:"
        echo "$response" | jq -r '.validation_errors[] | "  - \(.field): \(.message)"'
    fi
}

handle_unauthorized() {
    local response=$1
    local context=$2
    
    echo "❌ ERROR: Unauthorized (401)"
    echo "Context: $context"
    
    # Try different authentication error handlers
    handle_invalid_client "$response" || \
    handle_token_expired "$response" "401" || \
    echo "Generic authentication failure"
}

handle_forbidden() {
    local response=$1
    local context=$2
    
    echo "❌ ERROR: Forbidden (403)"
    echo "Context: $context"
    
    handle_insufficient_scope "$response" "403" || \
    echo "Access denied - check permissions"
}

handle_not_found() {
    local response=$1
    local context=$2
    
    echo "❌ ERROR: Not found (404)"
    echo "Context: $context"
    echo "Action: Verify endpoint URL and resource existence"
}

handle_conflict() {
    local response=$1
    local context=$2
    
    echo "❌ ERROR: Conflict (409)"
    echo "Context: $context"
    
    local conflict_reason=$(echo "$response" | jq -r '.error_description // "Resource conflict"')
    echo "Reason: $conflict_reason"
    echo "Action: Check for duplicate resources or concurrent modifications"
}

handle_unprocessable_entity() {
    local response=$1
    local context=$2
    
    echo "❌ ERROR: Unprocessable entity (422)"
    echo "Context: $context"
    
    if echo "$response" | jq -e '.errors' > /dev/null 2>&1; then
        echo "Validation errors:"
        echo "$response" | jq -r '.errors | to_entries[] | "  - \(.key): \(.value | join(", "))"'
    fi
}

reset_error_count() {
    local error_file="/tmp/error_count_$$"
    rm -f "$error_file"
}
```

## 🧪 Error Handling Test Suite

### Complete Error Testing Script

```bash
#!/bin/bash

# Error Handling Test Suite
echo "=== Service-to-Service Error Handling Test Suite ==="

# Load configuration
source service_config.env

# Test counters
TOTAL_ERROR_TESTS=0
PASSED_ERROR_TESTS=0

test_error_scenario() {
    local test_name=$1
    local expected_status=$2
    local curl_command=$3
    
    echo ""
    echo "Testing: $test_name"
    echo "Expected: HTTP $expected_status"
    
    TOTAL_ERROR_TESTS=$((TOTAL_ERROR_TESTS + 1))
    
    # Execute the curl command and capture response
    local response=$(eval "$curl_command" 2>&1)
    local actual_status=$(echo "$response" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
    
    if [ "$actual_status" = "$expected_status" ]; then
        echo "✅ PASS: Got expected status $actual_status"
        PASSED_ERROR_TESTS=$((PASSED_ERROR_TESTS + 1))
        
        # Test error handling function
        local body=$(echo "$response" | head -n -1)
        handle_api_response "$body" "$actual_status" "$test_name"
    else
        echo "❌ FAIL: Expected $expected_status, got $actual_status"
        echo "Response: $response"
    fi
}

# Run error tests
echo "Running authentication error tests..."

test_error_scenario "Invalid client credentials" "401" \
  "curl -k -s -w '\nHTTP_STATUS:%{http_code}' -X POST '${BASE_URL}/api/v1/auth/service-token' -H 'Content-Type: application/x-www-form-urlencoded' -d 'client_id=invalid&client_secret=invalid&grant_type=client_credentials'"

test_error_scenario "Missing authorization header" "401" \
  "curl -k -s -w '\nHTTP_STATUS:%{http_code}' -X GET '${BASE_URL}/api/v1/users/me'"

test_error_scenario "Invalid token format" "401" \
  "curl -k -s -w '\nHTTP_STATUS:%{http_code}' -X GET '${BASE_URL}/api/v1/users/me' -H 'Authorization: Bearer invalid.token.format'"

test_error_scenario "Nonexistent endpoint" "404" \
  "curl -k -s -w '\nHTTP_STATUS:%{http_code}' -X GET '${BASE_URL}/api/v1/nonexistent/endpoint' -H 'Authorization: Bearer ${VALID_TOKEN}'"

test_error_scenario "Invalid HTTP method" "405" \
  "curl -k -s -w '\nHTTP_STATUS:%{http_code}' -X PATCH '${BASE_URL}/api/v1/users/me' -H 'Authorization: Bearer ${VALID_TOKEN}'"

# Summary
echo ""
echo "=========================================="
echo "Error Handling Test Results"
echo "=========================================="
echo "Total Error Tests: $TOTAL_ERROR_TESTS"
echo "Passed: $PASSED_ERROR_TESTS"
echo "Failed: $((TOTAL_ERROR_TESTS - PASSED_ERROR_TESTS))"
echo "Success Rate: $(( (PASSED_ERROR_TESTS * 100) / TOTAL_ERROR_TESTS ))%"
echo ""

if [ $PASSED_ERROR_TESTS -eq $TOTAL_ERROR_TESTS ]; then
    echo "🎉 All error handling tests passed!"
    exit 0
else
    echo "⚠️  Some error handling tests failed"
    exit 1
fi
```

## 📋 Error Handling Checklist

### Pre-Production Validation

- [ ] **Authentication Errors**
  - [ ] Invalid client credentials handling
  - [ ] Token expiry detection and refresh
  - [ ] Scope validation and fallback

- [ ] **Authorization Errors**
  - [ ] Insufficient scope handling
  - [ ] Permission escalation requests
  - [ ] Graceful degradation

- [ ] **Network Errors**
  - [ ] Connection timeout handling
  - [ ] DNS resolution failures
  - [ ] SSL/TLS certificate issues

- [ ] **Rate Limiting**
  - [ ] 429 response handling
  - [ ] Exponential backoff implementation
  - [ ] Request queuing strategies

- [ ] **Server Errors**
  - [ ] 5xx error logging
  - [ ] Circuit breaker implementation
  - [ ] Fallback service mechanisms

- [ ] **Monitoring & Alerting**
  - [ ] Error rate monitoring
  - [ ] Security event logging
  - [ ] Performance degradation alerts

This comprehensive error handling guide ensures robust service-to-service communication with proper error recovery and monitoring capabilities.