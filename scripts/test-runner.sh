#!/bin/bash

# permiso Authentication System - Test Runner Script
# Comprehensive test execution with Poetry integration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Default values
TEST_TYPE="all"
COVERAGE_THRESHOLD=80
VERBOSE=false
PARALLEL=false
FAIL_FAST=false
GENERATE_REPORT=false
CLEANUP_AFTER=true
USE_DOCKER=false

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_test() {
    echo -e "${PURPLE}[TEST]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Run tests for permiso Authentication System with Poetry

OPTIONS:
    -t, --type TYPE         Test type (all|unit|integration|security|api|performance) [default: all]
    -c, --coverage NUM      Coverage threshold percentage [default: 80]
    -v, --verbose           Enable verbose output
    -p, --parallel          Run tests in parallel
    -f, --fail-fast         Stop on first failure
    -r, --report            Generate HTML coverage report
    -n, --no-cleanup        Don't cleanup after tests
    -d, --docker            Run tests in Docker container
    -h, --help              Show this help message

TEST TYPES:
    all            - Run all test suites
    unit           - Run unit tests only
    integration    - Run integration tests only
    security       - Run security tests only
    api            - Run API tests only
    performance    - Run performance tests only

EXAMPLES:
    # Run all tests with coverage
    $0

    # Run only unit tests with verbose output
    $0 --type unit --verbose

    # Run tests in parallel with HTML report
    $0 --parallel --report

    # Run security tests with fail-fast
    $0 --type security --fail-fast

    # Run tests in Docker container
    $0 --docker

EOF
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if [[ $USE_DOCKER == true ]]; then
        # Check Docker prerequisites
        if ! command -v docker &> /dev/null; then
            print_error "Docker is not installed or not in PATH"
            exit 1
        fi
        
        if ! docker info &> /dev/null; then
            print_error "Docker daemon is not running"
            exit 1
        fi
        
        if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
            print_error "Docker Compose is not installed"
            exit 1
        fi
    else
        # Check Poetry prerequisites
        if ! command -v poetry &> /dev/null; then
            print_error "Poetry is not installed or not in PATH"
            print_error "Install Poetry: curl -sSL https://install.python-poetry.org | python3 -"
            exit 1
        fi
        
        # Check if we're in a Poetry project
        if [[ ! -f "pyproject.toml" ]]; then
            print_error "Not in a Poetry project directory (pyproject.toml not found)"
            exit 1
        fi
        
        # Check if virtual environment is activated or available
        if [[ -z "$VIRTUAL_ENV" ]] && ! poetry env info &> /dev/null; then
            print_warning "No virtual environment detected. Poetry will create one."
        fi
    fi
    
    print_success "Prerequisites check passed"
}

# Function to setup test environment
setup_test_environment() {
    print_status "Setting up test environment..."
    
    if [[ $USE_DOCKER == true ]]; then
        # Start test services with Docker
        print_status "Starting test services with Docker..."
        docker-compose -f docker-compose.test.yml up -d postgres-test redis-test
        
        # Wait for services to be ready
        print_status "Waiting for test services to be ready..."
        sleep 15
        
        # Check service health
        if ! docker-compose -f docker-compose.test.yml exec -T postgres-test pg_isready -U permiso_test -d permiso_test; then
            print_error "PostgreSQL test service is not ready"
            exit 1
        fi
        
        if ! docker-compose -f docker-compose.test.yml exec -T redis-test redis-cli ping; then
            print_error "Redis test service is not ready"
            exit 1
        fi
    else
        # Set environment variables for local testing
        export ENVIRONMENT=testing
        export DATABASE_URL="postgresql+asyncpg://permiso_test:permiso_test_password@localhost:5433/permiso_test"
        export REDIS_URL="redis://localhost:6380/0"
        export JWT_SECRET_KEY="test-secret-key-for-testing-only"
        
        # Install dependencies if needed
        print_status "Installing test dependencies..."
        poetry install --with dev,test
    fi
    
    print_success "Test environment setup completed"
}

# Function to run database migrations
run_migrations() {
    print_status "Running database migrations..."
    
    if [[ $USE_DOCKER == true ]]; then
        docker-compose -f docker-compose.test.yml run --rm permiso-migrate-test
    else
        poetry run alembic upgrade head
    fi
    
    print_success "Database migrations completed"
}

# Function to build test command
build_test_command() {
    local cmd="pytest"
    local test_path=""
    
    # Set test path based on type
    case $TEST_TYPE in
        all)
            test_path="tests/"
            ;;
        unit)
            test_path="tests/unit/"
            ;;
        integration)
            test_path="tests/integration/"
            ;;
        security)
            test_path="tests/security/"
            ;;
        api)
            test_path="tests/test_app/test_api/"
            ;;
        performance)
            test_path="tests/performance/"
            ;;
        *)
            print_error "Invalid test type: $TEST_TYPE"
            exit 1
            ;;
    esac
    
    # Build command with options
    cmd="$cmd $test_path"
    
    # Add coverage options
    cmd="$cmd --cov=app --cov-report=term-missing --cov-fail-under=$COVERAGE_THRESHOLD"
    
    if [[ $GENERATE_REPORT == true ]]; then
        cmd="$cmd --cov-report=html"
    fi
    
    # Add verbosity
    if [[ $VERBOSE == true ]]; then
        cmd="$cmd -v"
    else
        cmd="$cmd --tb=short"
    fi
    
    # Add parallel execution
    if [[ $PARALLEL == true ]]; then
        cmd="$cmd -n auto"
    fi
    
    # Add fail-fast
    if [[ $FAIL_FAST == true ]]; then
        cmd="$cmd --maxfail=1"
    else
        cmd="$cmd --maxfail=5"
    fi
    
    # Add test markers
    case $TEST_TYPE in
        unit)
            cmd="$cmd -m unit"
            ;;
        integration)
            cmd="$cmd -m integration"
            ;;
        security)
            cmd="$cmd -m security"
            ;;
        performance)
            cmd="$cmd -m performance"
            ;;
    esac
    
    echo "$cmd"
}

# Function to run tests
run_tests() {
    print_test "Running $TEST_TYPE tests..."
    
    local test_cmd=$(build_test_command)
    local exit_code=0
    
    print_status "Test command: $test_cmd"
    
    if [[ $USE_DOCKER == true ]]; then
        # Run tests in Docker container
        docker-compose -f docker-compose.test.yml run --rm permiso-test bash -c "$test_cmd"
        exit_code=$?
    else
        # Run tests locally with Poetry
        poetry run $test_cmd
        exit_code=$?
    fi
    
    if [[ $exit_code -eq 0 ]]; then
        print_success "All tests passed!"
    else
        print_error "Tests failed with exit code $exit_code"
    fi
    
    return $exit_code
}

# Function to generate test report
generate_test_report() {
    if [[ $GENERATE_REPORT == true ]]; then
        print_status "Generating test report..."
        
        local report_dir="test-reports"
        local timestamp=$(date +"%Y%m%d_%H%M%S")
        
        mkdir -p "$report_dir"
        
        # Copy coverage report
        if [[ -d "htmlcov" ]]; then
            cp -r htmlcov "$report_dir/coverage_$timestamp"
            print_success "Coverage report generated: $report_dir/coverage_$timestamp/index.html"
        fi
        
        # Generate test summary
        cat > "$report_dir/test_summary_$timestamp.txt" << EOF
permiso Authentication System - Test Report
Generated: $(date)
Test Type: $TEST_TYPE
Coverage Threshold: $COVERAGE_THRESHOLD%
Parallel Execution: $PARALLEL
Docker Mode: $USE_DOCKER

Test Results:
$(if [[ $? -eq 0 ]]; then echo "✅ PASSED"; else echo "❌ FAILED"; fi)

For detailed coverage report, open: $report_dir/coverage_$timestamp/index.html
EOF
        
        print_success "Test summary generated: $report_dir/test_summary_$timestamp.txt"
    fi
}

# Function to cleanup
cleanup() {
    if [[ $CLEANUP_AFTER == true ]]; then
        print_status "Cleaning up test environment..."
        
        if [[ $USE_DOCKER == true ]]; then
            # Stop and remove test containers
            docker-compose -f docker-compose.test.yml down
            
            # Remove test volumes (optional)
            # docker-compose -f docker-compose.test.yml down -v
        fi
        
        print_success "Cleanup completed"
    fi
}

# Function to handle script interruption
handle_interrupt() {
    print_warning "Test execution interrupted"
    cleanup
    exit 130
}

# Set trap for cleanup on script interruption
trap handle_interrupt SIGINT SIGTERM

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            TEST_TYPE="$2"
            shift 2
            ;;
        -c|--coverage)
            COVERAGE_THRESHOLD="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -p|--parallel)
            PARALLEL=true
            shift
            ;;
        -f|--fail-fast)
            FAIL_FAST=true
            shift
            ;;
        -r|--report)
            GENERATE_REPORT=true
            shift
            ;;
        -n|--no-cleanup)
            CLEANUP_AFTER=false
            shift
            ;;
        -d|--docker)
            USE_DOCKER=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_status "Starting permiso Authentication System test execution..."
    print_status "Test type: $TEST_TYPE"
    print_status "Coverage threshold: $COVERAGE_THRESHOLD%"
    print_status "Docker mode: $USE_DOCKER"
    
    check_prerequisites
    setup_test_environment
    run_migrations
    
    local test_exit_code=0
    run_tests
    test_exit_code=$?
    
    generate_test_report
    cleanup
    
    if [[ $test_exit_code -eq 0 ]]; then
        print_success "Test execution completed successfully!"
        exit 0
    else
        print_error "Test execution failed!"
        exit $test_exit_code
    fi
}

# Run main function
main