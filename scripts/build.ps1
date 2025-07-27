# permiso Authentication System - Build Script (PowerShell)
# Supports development, testing, and production environments

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("development", "testing", "production")]
    [string]$Environment = "development",
    
    [Parameter(Mandatory=$false)]
    [switch]$Push,
    
    [Parameter(Mandatory=$false)]
    [switch]$Test,
    
    [Parameter(Mandatory=$false)]
    [switch]$Cleanup,
    
    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Colors for output
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Blue = "Cyan"

# Function to print colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Red
}

# Function to show usage
function Show-Usage {
    Write-Host @"
Usage: .\scripts\build.ps1 [OPTIONS]

Build permiso Authentication System for different environments

OPTIONS:
    -Environment ENV    Target environment (development|testing|production) [default: development]
    -Push              Push image to registry after build
    -Test              Run tests after build (only for testing environment)
    -Cleanup           Clean up intermediate containers and images
    -Help              Show this help message

EXAMPLES:
    # Build for development
    .\scripts\build.ps1 -Environment development

    # Build for testing and run tests
    .\scripts\build.ps1 -Environment testing -Test

    # Build for production and push to registry
    .\scripts\build.ps1 -Environment production -Push

    # Build with cleanup
    .\scripts\build.ps1 -Environment development -Cleanup

ENVIRONMENTS:
    development    - Development environment with hot reload and debug tools
    testing        - Testing environment with test dependencies and test runner
    production     - Production environment optimized for performance and security
"@
}

# Function to check prerequisites
function Test-Prerequisites {
    Write-Status "Checking prerequisites..."
    
    # Check if Docker is installed and running
    try {
        $dockerVersion = docker --version
        if (-not $dockerVersion) {
            throw "Docker not found"
        }
    }
    catch {
        Write-Error "Docker is not installed or not in PATH"
        exit 1
    }
    
    try {
        docker info | Out-Null
    }
    catch {
        Write-Error "Docker daemon is not running"
        exit 1
    }
    
    # Check if docker-compose is available
    try {
        $composeVersion = docker-compose --version
        if (-not $composeVersion) {
            # Try docker compose (newer syntax)
            docker compose version | Out-Null
        }
    }
    catch {
        Write-Error "Docker Compose is not installed"
        exit 1
    }
    
    # Check if we're in the right directory
    if (-not (Test-Path "pyproject.toml") -or -not (Test-Path "Dockerfile")) {
        Write-Error "Please run this script from the project root directory"
        exit 1
    }
    
    Write-Success "Prerequisites check passed"
}

# Function to set build arguments based on environment
function Get-BuildArgs {
    switch ($Environment) {
        "development" { return "--target development" }
        "testing" { return "--target testing" }
        "production" { return "--target production" }
    }
}

# Function to build Docker image
function Build-Image {
    Write-Status "Building Docker image for $Environment environment..."
    
    $imageName = "permiso-auth:$Environment"
    $buildArgs = Get-BuildArgs
    
    # Build the image
    $buildCommand = "docker build $buildArgs --tag $imageName --build-arg ENVIRONMENT=$Environment --build-arg BUILDKIT_INLINE_CACHE=1 ."
    
    Write-Status "Executing: $buildCommand"
    Invoke-Expression $buildCommand
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Docker image built successfully: $imageName"
    } else {
        Write-Error "Failed to build Docker image"
        exit 1
    }
}

# Function to run tests
function Invoke-Tests {
    if ($Environment -eq "testing" -and $Test) {
        Write-Status "Running tests in testing environment..."
        
        # Start test services
        docker-compose -f docker-compose.test.yml up -d postgres-test redis-test
        
        # Wait for services to be ready
        Write-Status "Waiting for test services to be ready..."
        Start-Sleep -Seconds 10
        
        # Run tests
        docker-compose -f docker-compose.test.yml run --rm permiso-test
        $testExitCode = $LASTEXITCODE
        
        # Stop test services
        docker-compose -f docker-compose.test.yml down
        
        if ($testExitCode -eq 0) {
            Write-Success "All tests passed!"
        } else {
            Write-Error "Tests failed with exit code $testExitCode"
            exit $testExitCode
        }
    }
}

# Function to push image to registry
function Push-Image {
    if ($Push) {
        Write-Status "Pushing image to registry..."
        
        $imageName = "permiso-auth:$Environment"
        
        # Tag for registry (customize this based on your registry)
        $registryImage = "your-registry.com/permiso-auth:$Environment"
        docker tag $imageName $registryImage
        
        # Push to registry
        docker push $registryImage
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Image pushed successfully: $registryImage"
        } else {
            Write-Error "Failed to push image to registry"
            exit 1
        }
    }
}

# Function to cleanup
function Invoke-Cleanup {
    if ($Cleanup) {
        Write-Status "Cleaning up intermediate containers and images..."
        
        # Remove dangling images
        docker image prune -f
        
        # Remove unused containers
        docker container prune -f
        
        Write-Success "Cleanup completed"
    }
}

# Main execution
function Main {
    if ($Help) {
        Show-Usage
        exit 0
    }
    
    Write-Status "Starting permiso Authentication System build process..."
    Write-Status "Environment: $Environment"
    
    Test-Prerequisites
    Build-Image
    Invoke-Tests
    Push-Image
    Invoke-Cleanup
    
    Write-Success "Build process completed successfully for $Environment environment!"
}

# Error handling
trap {
    Write-Error "An error occurred: $_"
    exit 1
}

# Run main function
Main