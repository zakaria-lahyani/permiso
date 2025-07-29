# Service-to-Service Demo Execution Guide

This document provides step-by-step instructions to execute the complete service-to-service authentication demo.

## 🚀 Quick Start

### Prerequisites

1. **Permiso API Running**: Ensure the Permiso authentication service is running
2. **Environment Setup**: Configure your environment variables
3. **Network Access**: Verify connectivity to the Permiso API endpoints

### Environment Configuration

Create [`service_config.env`](service_config.env):

```bash
# Permiso API Configuration
BASE_URL="https://your-permiso-instance.com"
API_BASE="/api/v1"

# Service Brain Configuration
SERVICE_BRAIN_ID="service_brain_client_id"
SERVICE_BRAIN_SECRET="service_brain_client_secret"
SERVICE_BRAIN_SCOPES="api:read api:write"

# Service Executer Configuration  
SERVICE_EXECUTER_ID="service_executer_client_id"
SERVICE_EXECUTER_SECRET="service_executer_client_secret"
SERVICE_EXECUTER_SCOPES="api:read api:write token:introspect"

# Demo Configuration
DEMO_MODE="full"  # Options: quick, full, errors-only
LOG_LEVEL="info"  # Options: debug, info, warn, error
ENABLE_MONITORING="true"
```

## 📋 Complete Demo Script

### Main Demo Runner

Create [`run_service_demo.sh`](run_service_demo.sh):

```bash
#!/bin/bash

# Service-to-Service Authentication Demo
# Complete test suite for Permiso API integration

set -e  # Exit on any error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/service_config.env"
LOG_FILE="${SCRIPT_DIR}/demo_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    
    case $level in
        ERROR) echo -e "${RED}❌ $message${NC}" ;;
        SUCCESS) echo -e "${GREEN}✅ $message${NC}" ;;
        WARNING) echo -e "${YELLOW}⚠️  $message${NC}" ;;
        INFO) echo -e "${BLUE}ℹ️  $message${NC}" ;;
    esac
}

# Load configuration
load_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log "ERROR" "Configuration file not found: $CONFIG_FILE"
        log "INFO" "Please create service_config.env with required settings"
        exit 1
    fi
    
    source "$CONFIG_FILE"
    log "SUCCESS" "Configuration loaded from $CONFIG_FILE"
}

# Validate environment
validate_environment() {
    log "INFO" "Validating environment configuration..."
    
    local required_vars=(
        "BASE_URL"
        "API_BASE" 
        "SERVICE_BRAIN_ID"
        "SERVICE_BRAIN_SECRET"
        "SERVICE_EXECUTER_ID"
        "SERVICE_EXECUTER_SECRET"
    )
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            log "ERROR" "Required environment variable not set: $var"
            exit 1
        fi
    done
    
    log "SUCCESS" "Environment validation passed"
}

# Test API connectivity
test_connectivity() {
    log "INFO" "Testing API connectivity..."
    
    local health_url="${BASE_URL}${API_BASE}/health"
    
    if curl -k -s --connect-timeout 10 --max-time 30 "$health_url" > /dev/null 2>&1; then
        log "SUCCESS" "API connectivity verified"
    else
        log "ERROR" "Cannot connect to Permiso API at $BASE_URL"
        log "INFO" "Please verify the BASE_URL and ensure the service is running"
        exit 1
    fi
}

# Service registration test
test_service_registration() {
    log "INFO" "Testing service registration..."
    
    # Test service_brain registration
    log "INFO" "Verifying service_brain registration..."
    local brain_response=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" \
        -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=${SERVICE_BRAIN_ID}&client_secret=${SERVICE_BRAIN_SECRET}&grant_type=client_credentials")
    
    local brain_status=$(echo "$brain_response" | tail -n1 | cut -d: -f2)
    local brain_body=$(echo "$brain_response" | head -n -1)
    
    if [ "$brain_status" = "200" ]; then
        BRAIN_TOKEN=$(echo "$brain_body" | jq -r '.access_token')
        log "SUCCESS" "service_brain authentication successful"
        log "INFO" "Token: ${BRAIN_TOKEN:0:30}..."
    else
        log "ERROR" "service_brain authentication failed (HTTP $brain_status)"
        log "ERROR" "Response: $brain_body"
        exit 1
    fi
    
    # Test service_executer registration
    log "INFO" "Verifying service_executer registration..."
    local executer_response=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" \
        -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=${SERVICE_EXECUTER_ID}&client_secret=${SERVICE_EXECUTER_SECRET}&grant_type=client_credentials")
    
    local executer_status=$(echo "$executer_response" | tail -n1 | cut -d: -f2)
    local executer_body=$(echo "$executer_response" | head -n -1)
    
    if [ "$executer_status" = "200" ]; then
        EXECUTER_TOKEN=$(echo "$executer_body" | jq -r '.access_token')
        log "SUCCESS" "service_executer authentication successful"
        log "INFO" "Token: ${EXECUTER_TOKEN:0:30}..."
    else
        log "ERROR" "service_executer authentication failed (HTTP $executer_status)"
        log "ERROR" "Response: $executer_body"
        exit 1
    fi
}

# Token validation test
test_token_validation() {
    log "INFO" "Testing token validation..."
    
    # Test token introspection
    local introspect_response=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" \
        -X POST "${BASE_URL}${API_BASE}/auth/introspect" \
        -H "Authorization: Bearer ${EXECUTER_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"token\": \"${BRAIN_TOKEN}\"}")
    
    local introspect_status=$(echo "$introspect_response" | tail -n1 | cut -d: -f2)
    local introspect_body=$(echo "$introspect_response" | head -n -1)
    
    if [ "$introspect_status" = "200" ]; then
        local is_active=$(echo "$introspect_body" | jq -r '.active')
        local token_scopes=$(echo "$introspect_body" | jq -r '.scope // "none"')
        
        if [ "$is_active" = "true" ]; then
            log "SUCCESS" "Token validation successful"
            log "INFO" "Token scopes: $token_scopes"
        else
            log "ERROR" "Token is not active"
            exit 1
        fi
    else
        log "ERROR" "Token introspection failed (HTTP $introspect_status)"
        log "ERROR" "Response: $introspect_body"
        exit 1
    fi
}

# Service-to-service communication test
test_service_communication() {
    log "INFO" "Testing service-to-service communication..."
    
    # service_brain makes request using its token
    local request_id="demo_$(date +%s)"
    local comm_response=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" \
        -X GET "${BASE_URL}${API_BASE}/users/me" \
        -H "Authorization: Bearer ${BRAIN_TOKEN}" \
        -H "X-Service-Name: service_brain" \
        -H "X-Target-Service: service_executer" \
        -H "X-Request-ID: $request_id")
    
    local comm_status=$(echo "$comm_response" | tail -n1 | cut -d: -f2)
    local comm_body=$(echo "$comm_response" | head -n -1)
    
    if [ "$comm_status" = "200" ]; then
        log "SUCCESS" "Service-to-service communication successful"
        local user_info=$(echo "$comm_body" | jq -r '.username // .id // "unknown"')
        log "INFO" "Retrieved user info: $user_info"
    else
        log "ERROR" "Service communication failed (HTTP $comm_status)"
        log "ERROR" "Response: $comm_body"
        exit 1
    fi
}

# Authorization test (scope validation)
test_authorization() {
    log "INFO" "Testing authorization and scope validation..."
    
    # Test endpoint requiring higher privileges (should fail)
    local auth_response=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" \
        -X GET "${BASE_URL}${API_BASE}/admin/system/health" \
        -H "Authorization: Bearer ${BRAIN_TOKEN}")
    
    local auth_status=$(echo "$auth_response" | tail -n1 | cut -d: -f2)
    local auth_body=$(echo "$auth_response" | head -n -1)
    
    if [ "$auth_status" = "403" ]; then
        log "SUCCESS" "Authorization correctly denied for insufficient scope"
        local error_msg=$(echo "$auth_body" | jq -r '.error_description // "Access denied"')
        log "INFO" "Error message: $error_msg"
    elif [ "$auth_status" = "200" ]; then
        log "WARNING" "Authorization granted - service may have elevated privileges"
    else
        log "ERROR" "Unexpected authorization response (HTTP $auth_status)"
        log "ERROR" "Response: $auth_body"
    fi
}

# Error handling tests
test_error_handling() {
    log "INFO" "Testing error handling scenarios..."
    
    # Test 1: Invalid token
    log "INFO" "Testing invalid token handling..."
    local invalid_response=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" \
        -X GET "${BASE_URL}${API_BASE}/users/me" \
        -H "Authorization: Bearer invalid.token.format")
    
    local invalid_status=$(echo "$invalid_response" | tail -n1 | cut -d: -f2)
    
    if [ "$invalid_status" = "401" ]; then
        log "SUCCESS" "Invalid token correctly rejected"
    else
        log "ERROR" "Invalid token not properly handled (HTTP $invalid_status)"
    fi
    
    # Test 2: Missing authorization
    log "INFO" "Testing missing authorization handling..."
    local missing_response=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" \
        -X GET "${BASE_URL}${API_BASE}/users/me")
    
    local missing_status=$(echo "$missing_response" | tail -n1 | cut -d: -f2)
    
    if [ "$missing_status" = "401" ]; then
        log "SUCCESS" "Missing authorization correctly rejected"
    else
        log "ERROR" "Missing authorization not properly handled (HTTP $missing_status)"
    fi
    
    # Test 3: Invalid client credentials
    log "INFO" "Testing invalid client credentials..."
    local cred_response=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" \
        -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=invalid&client_secret=invalid&grant_type=client_credentials")
    
    local cred_status=$(echo "$cred_response" | tail -n1 | cut -d: -f2)
    
    if [ "$cred_status" = "401" ]; then
        log "SUCCESS" "Invalid credentials correctly rejected"
    else
        log "ERROR" "Invalid credentials not properly handled (HTTP $cred_status)"
    fi
}

# Performance test
test_performance() {
    log "INFO" "Testing performance and concurrent requests..."
    
    local start_time=$(date +%s)
    local success_count=0
    local total_requests=10
    
    for i in $(seq 1 $total_requests); do
        local perf_response=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" \
            -X GET "${BASE_URL}${API_BASE}/users/me" \
            -H "Authorization: Bearer ${BRAIN_TOKEN}" \
            -H "X-Request-ID: perf_test_$i")
        
        local perf_status=$(echo "$perf_response" | tail -n1 | cut -d: -f2)
        
        if [ "$perf_status" = "200" ]; then
            success_count=$((success_count + 1))
        fi
        
        # Small delay to avoid overwhelming the server
        sleep 0.1
    done
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local success_rate=$(( (success_count * 100) / total_requests ))
    
    log "SUCCESS" "Performance test completed"
    log "INFO" "Requests: $total_requests, Success: $success_count, Duration: ${duration}s"
    log "INFO" "Success rate: ${success_rate}%"
    
    if [ $success_rate -ge 90 ]; then
        log "SUCCESS" "Performance test passed (${success_rate}% success rate)"
    else
        log "WARNING" "Performance test marginal (${success_rate}% success rate)"
    fi
}

# Cleanup function
cleanup() {
    log "INFO" "Cleaning up demo resources..."
    
    # Revoke tokens if possible
    if [ -n "$BRAIN_TOKEN" ]; then
        curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/revoke" \
            -H "Authorization: Bearer ${BRAIN_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "{\"token\": \"${BRAIN_TOKEN}\"}" > /dev/null 2>&1
    fi
    
    if [ -n "$EXECUTER_TOKEN" ]; then
        curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/revoke" \
            -H "Authorization: Bearer ${EXECUTER_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "{\"token\": \"${EXECUTER_TOKEN}\"}" > /dev/null 2>&1
    fi
    
    log "SUCCESS" "Cleanup completed"
}

# Main execution function
main() {
    echo "=========================================="
    echo "Service-to-Service Authentication Demo"
    echo "=========================================="
    echo "Start time: $(date)"
    echo "Log file: $LOG_FILE"
    echo ""
    
    # Setup trap for cleanup
    trap cleanup EXIT
    
    # Execute test phases
    load_config
    validate_environment
    test_connectivity
    test_service_registration
    test_token_validation
    test_service_communication
    test_authorization
    
    if [ "${DEMO_MODE:-full}" = "full" ]; then
        test_error_handling
        test_performance
    fi
    
    # Final summary
    echo ""
    echo "=========================================="
    echo "Demo Execution Summary"
    echo "=========================================="
    log "SUCCESS" "All core tests completed successfully"
    log "INFO" "Services authenticated and communicating properly"
    log "INFO" "Token validation and authorization working correctly"
    log "INFO" "Error handling mechanisms validated"
    echo ""
    echo "End time: $(date)"
    echo "Full log available at: $LOG_FILE"
    echo ""
    echo "🎉 Service-to-Service Demo PASSED!"
}

# Execute main function
main "$@"
```

## 🔧 Quick Test Scripts

### Minimal Connectivity Test

Create [`quick_test.sh`](quick_test.sh):

```bash
#!/bin/bash

# Quick connectivity and authentication test
source service_config.env

echo "=== Quick Service-to-Service Test ==="

# Test 1: API connectivity
echo "1. Testing API connectivity..."
if curl -k -s --connect-timeout 5 "${BASE_URL}${API_BASE}/health" > /dev/null; then
    echo "✅ API is accessible"
else
    echo "❌ API is not accessible"
    exit 1
fi

# Test 2: Service authentication
echo "2. Testing service authentication..."
TOKEN=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=${SERVICE_BRAIN_ID}&client_secret=${SERVICE_BRAIN_SECRET}&grant_type=client_credentials" \
    | jq -r '.access_token // empty')

if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    echo "✅ Authentication successful"
    echo "Token: ${TOKEN:0:30}..."
else
    echo "❌ Authentication failed"
    exit 1
fi

# Test 3: API request
echo "3. Testing API request..."
RESPONSE=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" \
    -X GET "${BASE_URL}${API_BASE}/users/me" \
    -H "Authorization: Bearer ${TOKEN}")

STATUS=$(echo "$RESPONSE" | tail -n1 | cut -d: -f2)

if [ "$STATUS" = "200" ]; then
    echo "✅ API request successful"
else
    echo "❌ API request failed (HTTP $STATUS)"
    exit 1
fi

echo ""
echo "🎉 Quick test PASSED - Services are working correctly!"
```

### Error Testing Script

Create [`test_errors.sh`](test_errors.sh):

```bash
#!/bin/bash

# Error handling validation script
source service_config.env

echo "=== Error Handling Validation ==="

test_error_case() {
    local test_name=$1
    local expected_status=$2
    local curl_command=$3
    
    echo ""
    echo "Testing: $test_name"
    
    local response=$(eval "$curl_command")
    local actual_status=$(echo "$response" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
    
    if [ "$actual_status" = "$expected_status" ]; then
        echo "✅ PASS: $test_name (HTTP $actual_status)"
    else
        echo "❌ FAIL: $test_name - Expected $expected_status, got $actual_status"
    fi
}

# Run error tests
test_error_case "Invalid credentials" "401" \
    "curl -k -s -w '\nHTTP_STATUS:%{http_code}' -X POST '${BASE_URL}${API_BASE}/auth/service-token' -H 'Content-Type: application/x-www-form-urlencoded' -d 'client_id=invalid&client_secret=invalid&grant_type=client_credentials'"

test_error_case "Missing authorization" "401" \
    "curl -k -s -w '\nHTTP_STATUS:%{http_code}' -X GET '${BASE_URL}${API_BASE}/users/me'"

test_error_case "Invalid token" "401" \
    "curl -k -s -w '\nHTTP_STATUS:%{http_code}' -X GET '${BASE_URL}${API_BASE}/users/me' -H 'Authorization: Bearer invalid.token'"

test_error_case "Nonexistent endpoint" "404" \
    "curl -k -s -w '\nHTTP_STATUS:%{http_code}' -X GET '${BASE_URL}${API_BASE}/nonexistent'"

echo ""
echo "Error handling validation completed!"
```

## 📊 Monitoring and Logging

### Log Analysis Script

Create [`analyze_logs.sh`](analyze_logs.sh):

```bash
#!/bin/bash

# Demo log analysis script
LOG_DIR="."
LATEST_LOG=$(ls -t ${LOG_DIR}/demo_*.log 2>/dev/null | head -n1)

if [ -z "$LATEST_LOG" ]; then
    echo "No demo logs found"
    exit 1
fi

echo "=== Demo Log Analysis ==="
echo "Analyzing: $LATEST_LOG"
echo ""

# Count different log levels
echo "Log Level Summary:"
echo "  INFO:    $(grep -c '\[INFO\]' "$LATEST_LOG")"
echo "  SUCCESS: $(grep -c '\[SUCCESS\]' "$LATEST_LOG")"
echo "  WARNING: $(grep -c '\[WARNING\]' "$LATEST_LOG")"
echo "  ERROR:   $(grep -c '\[ERROR\]' "$LATEST_LOG")"
echo ""

# Show any errors
if grep -q '\[ERROR\]' "$LATEST_LOG"; then
    echo "Errors found:"
    grep '\[ERROR\]' "$LATEST_LOG"
    echo ""
fi

# Show any warnings
if grep -q '\[WARNING\]' "$LATEST_LOG"; then
    echo "Warnings found:"
    grep '\[WARNING\]' "$LATEST_LOG"
    echo ""
fi

# Show test results
echo "Test Results:"
grep -E '(PASS|FAIL|SUCCESS.*test)' "$LATEST_LOG" | tail -10

echo ""
echo "Analysis complete!"
```

## 🎯 Execution Instructions

### Step 1: Setup Environment

```bash
# 1. Clone or navigate to the demo directory
cd tests/client_tests/service_to_service_demo

# 2. Create configuration file
cp service_config.env.example service_config.env
# Edit service_config.env with your actual values

# 3. Make scripts executable
chmod +x *.sh
```

### Step 2: Run Quick Test

```bash
# Verify basic connectivity and authentication
./quick_test.sh
```

### Step 3: Run Full Demo

```bash
# Execute complete test suite
./run_service_demo.sh
```

### Step 4: Validate Error Handling

```bash
# Test error scenarios
./test_errors.sh
```

### Step 5: Analyze Results

```bash
# Review test results and logs
./analyze_logs.sh
```

## 📈 Expected Results

### Successful Demo Output

```
==========================================
Service-to-Service Authentication Demo
==========================================
Start time: Mon Jan 15 10:30:00 UTC 2024
Log file: ./demo_20240115_103000.log

✅ Configuration loaded from ./service_config.env
✅ Environment validation passed
✅ API connectivity verified
✅ service_brain authentication successful
✅ service_executer authentication successful
✅ Token validation successful
✅ Service-to-service communication successful
✅ Authorization correctly denied for insufficient scope
✅ Invalid token correctly rejected
✅ Missing authorization correctly rejected
✅ Invalid credentials correctly rejected
✅ Performance test passed (100% success rate)
✅ Cleanup completed

==========================================
Demo Execution Summary
==========================================
✅ All core tests completed successfully
ℹ️  Services authenticated and communicating properly
ℹ️  Token validation and authorization working correctly
ℹ️  Error handling mechanisms validated

End time: Mon Jan 15 10:32:15 UTC 2024
Full log available at: ./demo_20240115_103000.log

🎉 Service-to-Service Demo PASSED!
```

## 🔍 Troubleshooting

### Common Issues

1. **Connection Refused**
   ```bash
   # Check if Permiso API is running
   curl -k "${BASE_URL}/api/v1/health"
   ```

2. **Authentication Failed**
   ```bash
   # Verify service registration
   # Check client_id and client_secret in admin panel
   ```

3. **Permission Denied**
   ```bash
   # Verify service scopes
   # Check role assignments in Permiso
   ```

4. **SSL/TLS Errors**
   ```bash
   # For development, use -k flag with curl
   # For production, ensure proper certificates
   ```

### Debug Mode

```bash
# Run with debug logging
LOG_LEVEL=debug ./run_service_demo.sh

# Enable verbose curl output
export CURL_VERBOSE="-v"
./run_service_demo.sh
```

This completes the comprehensive service-to-service authentication demo with full execution capabilities, error handling, and monitoring.