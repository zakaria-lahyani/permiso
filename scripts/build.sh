#!/bin/bash

# permiso Authentication System - Build Script
# Supports development, testing, and production environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT="development"
BUILD_ARGS=""
PUSH_IMAGE=false
RUN_TESTS=false
CLEANUP=false

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

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Build permiso Authentication System for different environments

OPTIONS:
    -e, --environment ENV    Target environment (development|testing|production) [default: development]
    -p, --push              Push image to registry after build
    -t, --test              Run tests after build (only for testing environment)
    -c, --cleanup           Clean up intermediate containers and images
    -h, --help              Show this help message

EXAMPLES:
    # Build for development
    $0 -e development

    # Build for testing and run tests
    $0 -e testing --test

    # Build for production and push to registry
    $0 -e production --push

    # Build with cleanup
    $0 -e development --cleanup

ENVIRONMENTS:
    development    - Development environment with hot reload and debug tools
    testing        - Testing environment with test dependencies and test runner
    production     - Production environment optimized for performance and security

EOF
}

# Function to validate environment
validate_environment() {
    case $ENVIRONMENT in
        development|testing|production)
            print_status "Building for $ENVIRONMENT environment"
            ;;
        *)
            print_error "Invalid environment: $ENVIRONMENT"
            print_error "Valid environments: development, testing, production"
            exit 1
            ;;
    esac
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if Docker is installed and running
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check if docker-compose is available
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check if we're in the right directory
    if [[ ! -f "pyproject.toml" ]] || [[ ! -f "Dockerfile" ]]; then
        print_error "Please run this script from the project root directory"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Function to set build arguments based on environment
set_build_args() {
    case $ENVIRONMENT in
        development)
            BUILD_ARGS="--target development"
            ;;
        testing)
            BUILD_ARGS="--target testing"
            ;;
        production)
            BUILD_ARGS="--target production"
            ;;
    esac
}

# Function to build Docker image
build_image() {
    print_status "Building Docker image for $ENVIRONMENT environment..."
    
    IMAGE_NAME="permiso-auth:$ENVIRONMENT"
    
    # Build the image
    docker build \
        $BUILD_ARGS \
        --tag $IMAGE_NAME \
        --build-arg ENVIRONMENT=$ENVIRONMENT \
        --build-arg BUILDKIT_INLINE_CACHE=1 \
        .
    
    if [[ $? -eq 0 ]]; then
        print_success "Docker image built successfully: $IMAGE_NAME"
    else
        print_error "Failed to build Docker image"
        exit 1
    fi
}

# Function to run tests
run_tests() {
    if [[ $ENVIRONMENT == "testing" ]] && [[ $RUN_TESTS == true ]]; then
        print_status "Running tests in testing environment..."
        
        # Start test services
        docker-compose -f docker-compose.test.yml up -d postgres-test redis-test
        
        # Wait for services to be ready
        print_status "Waiting for test services to be ready..."
        sleep 10
        
        # Run tests
        docker-compose -f docker-compose.test.yml run --rm permiso-test
        
        TEST_EXIT_CODE=$?
        
        # Stop test services
        docker-compose -f docker-compose.test.yml down
        
        if [[ $TEST_EXIT_CODE -eq 0 ]]; then
            print_success "All tests passed!"
        else
            print_error "Tests failed with exit code $TEST_EXIT_CODE"
            exit $TEST_EXIT_CODE
        fi
    fi
}

# Function to push image to registry
push_image() {
    if [[ $PUSH_IMAGE == true ]]; then
        print_status "Pushing image to registry..."
        
        IMAGE_NAME="permiso-auth:$ENVIRONMENT"
        
        # Tag for registry (customize this based on your registry)
        REGISTRY_IMAGE="your-registry.com/permiso-auth:$ENVIRONMENT"
        docker tag $IMAGE_NAME $REGISTRY_IMAGE
        
        # Push to registry
        docker push $REGISTRY_IMAGE
        
        if [[ $? -eq 0 ]]; then
            print_success "Image pushed successfully: $REGISTRY_IMAGE"
        else
            print_error "Failed to push image to registry"
            exit 1
        fi
    fi
}

# Function to cleanup
cleanup() {
    if [[ $CLEANUP == true ]]; then
        print_status "Cleaning up intermediate containers and images..."
        
        # Remove dangling images
        docker image prune -f
        
        # Remove unused containers
        docker container prune -f
        
        print_success "Cleanup completed"
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -p|--push)
            PUSH_IMAGE=true
            shift
            ;;
        -t|--test)
            RUN_TESTS=true
            shift
            ;;
        -c|--cleanup)
            CLEANUP=true
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
    print_status "Starting permiso Authentication System build process..."
    
    validate_environment
    check_prerequisites
    set_build_args
    build_image
    run_tests
    push_image
    cleanup
    
    print_success "Build process completed successfully for $ENVIRONMENT environment!"
}

# Run main function
main