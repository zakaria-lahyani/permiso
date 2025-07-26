#!/bin/bash
# Test runner script for Keystone Authentication System

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
}

# Function to wait for services to be healthy
wait_for_services() {
    print_status "Waiting for services to be healthy..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose ps | grep -q "healthy"; then
            print_success "Services are healthy!"
            return 0
        fi
        
        print_status "Attempt $attempt/$max_attempts - Services not ready yet..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    print_error "Services failed to become healthy within timeout"
    docker-compose ps
    exit 1
}

# Function to run specific test types
run_tests() {
    local test_type=${1:-"all"}
    
    print_status "Running $test_type tests..."
    
    case $test_type in
        "unit")
            docker-compose exec keystone-dev poetry run pytest tests/test_app/ -m unit -v --tb=short
            ;;
        "integration")
            docker-compose exec keystone-dev poetry run pytest tests/integration/ -m integration -v --tb=short
            ;;
        "security")
            docker-compose exec keystone-dev poetry run pytest tests/security/ -m security -v --tb=short
            ;;
        "fast")
            docker-compose exec keystone-dev poetry run pytest -m "not slow" -v --tb=short
            ;;
        "coverage")
            docker-compose exec keystone-dev poetry run pytest --cov=app --cov-report=html --cov-report=term --cov-report=xml --cov-fail-under=80
            ;;
        "all")
            docker-compose exec keystone-dev poetry run pytest --cov=app --cov-report=html --cov-report=term -v
            ;;
        *)
            print_error "Unknown test type: $test_type"
            echo "Available options: unit, integration, security, fast, coverage, all"
            exit 1
            ;;
    esac
}

# Function to run tests in dedicated test container
run_tests_container() {
    print_status "Running tests in dedicated test container..."
    docker-compose --profile test up --build keystone-test
}

# Function to setup development environment
setup_dev() {
    print_status "Setting up development environment..."
    
    # Start services
    docker-compose up -d postgres redis postgres-test redis-test
    
    # Wait for services
    wait_for_services
    
    # Build and start dev container
    docker-compose up -d keystone-dev
    
    # Run database migrations
    print_status "Running database migrations..."
    docker-compose exec keystone-dev poetry run alembic upgrade head
    
    print_success "Development environment is ready!"
    print_status "You can now run: docker-compose exec keystone-dev bash"
}

# Function to cleanup
cleanup() {
    print_status "Cleaning up..."
    docker-compose down -v
    docker system prune -f
    print_success "Cleanup completed!"
}

# Function to show logs
show_logs() {
    local service=${1:-""}
    if [ -n "$service" ]; then
        docker-compose logs -f "$service"
    else
        docker-compose logs -f
    fi
}

# Function to run import tests
test_imports() {
    print_status "Testing imports..."
    docker-compose exec keystone-dev poetry run python tests/test_import.py
}

# Function to run specific test file
run_test_file() {
    local test_file=$1
    if [ -z "$test_file" ]; then
        print_error "Please specify a test file"
        exit 1
    fi
    
    print_status "Running test file: $test_file"
    docker-compose exec keystone-dev poetry run pytest "$test_file" -v
}

# Main script logic
main() {
    check_docker
    
    case ${1:-"help"} in
        "setup")
            setup_dev
            ;;
        "test")
            run_tests "${2:-all}"
            ;;
        "test-container")
            run_tests_container
            ;;
        "imports")
            test_imports
            ;;
        "file")
            run_test_file "$2"
            ;;
        "logs")
            show_logs "$2"
            ;;
        "cleanup")
            cleanup
            ;;
        "help"|*)
            echo "Keystone Test Runner"
            echo ""
            echo "Usage: $0 <command> [options]"
            echo ""
            echo "Commands:"
            echo "  setup              Set up development environment"
            echo "  test [type]        Run tests (unit|integration|security|fast|coverage|all)"
            echo "  test-container     Run tests in dedicated container"
            echo "  imports            Test import functionality"
            echo "  file <path>        Run specific test file"
            echo "  logs [service]     Show logs for service or all services"
            echo "  cleanup            Clean up containers and volumes"
            echo "  help               Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 setup"
            echo "  $0 test unit"
            echo "  $0 test coverage"
            echo "  $0 file tests/test_app/test_models/test_user.py"
            echo "  $0 logs keystone-dev"
            ;;
    esac
}

# Run main function with all arguments
main "$@"