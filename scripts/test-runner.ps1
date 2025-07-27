# permiso Authentication System - Test Runner Script (PowerShell)
# Comprehensive test execution with Poetry integration

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("all", "unit", "integration", "security", "api", "performance")]
    [string]$Type = "all",
    
    [Parameter(Mandatory=$false)]
    [int]$Coverage = 80,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose,
    
    [Parameter(Mandatory=$false)]
    [switch]$Parallel,
    
    [Parameter(Mandatory=$false)]
    [switch]$FailFast,
    
    [Parameter(Mandatory=$false)]
    [switch]$Report,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoCleanup,
    
    [Parameter(Mandatory=$false)]
    [switch]$Docker,
    
    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Colors for output
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Blue = "Cyan"
$Purple = "Magenta"

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

function Write-Test {
    param([string]$Message)
    Write-Host "[TEST] $Message" -ForegroundColor $Purple
}

# Function to show usage
function Show-Usage {
    Write-Host @"
Usage: .\scripts\test-runner.ps1 [OPTIONS]

Run tests for permiso Authentication System with Poetry

OPTIONS:
    -Type TYPE         Test type (all|unit|integration|security|api|performance) [default: all]
    -Coverage NUM      Coverage threshold percentage [default: 80]
    -Verbose           Enable verbose output
    -Parallel          Run tests in parallel
    -FailFast          Stop on first failure
    -Report            Generate HTML coverage report
    -NoCleanup         Don't cleanup after tests
    -Docker            Run tests in Docker container
    -Help              Show this help message

TEST TYPES:
    all            - Run all test suites
    unit           - Run unit tests only
    integration    - Run integration tests only
    security       - Run security tests only
    api            - Run API tests only
    performance    - Run performance tests only

EXAMPLES:
    # Run all tests with coverage
    .\scripts\test-runner.ps1

    # Run only unit tests with verbose output
    .\scripts\test-runner.ps1 -Type unit -Verbose

    # Run tests in parallel with HTML report
    .\scripts\test-runner.ps1 -Parallel -Report

    # Run security tests with fail-fast
    .\scripts\test-runner.ps1 -Type security -FailFast

    # Run tests in Docker container
    .\scripts\test-runner.ps1 -Docker
"@
}

# Function to check prerequisites
function Test-Prerequisites {
    Write-Status "Checking prerequisites..."
    
    if ($Docker) {
        # Check Docker prerequisites
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
        
        try {
            $composeVersion = docker-compose --version
            if (-not $composeVersion) {
                docker compose version | Out-Null
            }
        }
        catch {
            Write-Error "Docker Compose is not installed"
            exit 1
        }
    } else {
        # Check Poetry prerequisites
        try {
            $poetryVersion = poetry --version
            if (-not $poetryVersion) {
                throw "Poetry not found"
            }
        }
        catch {
            Write-Error "Poetry is not installed or not in PATH"
            Write-Error "Install Poetry: https://python-poetry.org/docs/#installation"
            exit 1
        }
        
        # Check if we're in a Poetry project
        if (-not (Test-Path "pyproject.toml")) {
            Write-Error "Not in a Poetry project directory (pyproject.toml not found)"
            exit 1
        }
        
        # Check if virtual environment is available
        try {
            poetry env info | Out-Null
        }
        catch {
            Write-Warning "No virtual environment detected. Poetry will create one."
        }
    }
    
    Write-Success "Prerequisites check passed"
}

# Function to setup test environment
function Initialize-TestEnvironment {
    Write-Status "Setting up test environment..."
    
    if ($Docker) {
        # Start test services with Docker
        Write-Status "Starting test services with Docker..."
        docker-compose -f docker-compose.test.yml up -d postgres-test redis-test
        
        # Wait for services to be ready
        Write-Status "Waiting for test services to be ready..."
        Start-Sleep -Seconds 15
        
        # Check service health
        try {
            docker-compose -f docker-compose.test.yml exec -T postgres-test pg_isready -U permiso_test -d permiso_test
            if ($LASTEXITCODE -ne 0) {
                throw "PostgreSQL not ready"
            }
        }
        catch {
            Write-Error "PostgreSQL test service is not ready"
            exit 1
        }
        
        try {
            docker-compose -f docker-compose.test.yml exec -T redis-test redis-cli ping
            if ($LASTEXITCODE -ne 0) {
                throw "Redis not ready"
            }
        }
        catch {
            Write-Error "Redis test service is not ready"
            exit 1
        }
    } else {
        # Set environment variables for local testing
        $env:ENVIRONMENT = "testing"
        $env:DATABASE_URL = "postgresql+asyncpg://permiso_test:permiso_test_password@localhost:5433/permiso_test"
        $env:REDIS_URL = "redis://localhost:6380/0"
        $env:JWT_SECRET_KEY = "test-secret-key-for-testing-only"
        
        # Install dependencies if needed
        Write-Status "Installing test dependencies..."
        poetry install --with dev,test
    }
    
    Write-Success "Test environment setup completed"
}

# Function to run database migrations
function Invoke-Migrations {
    Write-Status "Running database migrations..."
    
    if ($Docker) {
        docker-compose -f docker-compose.test.yml run --rm permiso-migrate-test
    } else {
        poetry run alembic upgrade head
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Database migrations completed"
    } else {
        Write-Error "Database migrations failed"
        exit 1
    }
}

# Function to build test command
function Get-TestCommand {
    $cmd = "pytest"
    $testPath = ""
    
    # Set test path based on type
    switch ($Type) {
        "all" { $testPath = "tests/" }
        "unit" { $testPath = "tests/unit/" }
        "integration" { $testPath = "tests/integration/" }
        "security" { $testPath = "tests/security/" }
        "api" { $testPath = "tests/test_app/test_api/" }
        "performance" { $testPath = "tests/performance/" }
        default {
            Write-Error "Invalid test type: $Type"
            exit 1
        }
    }
    
    # Build command with options
    $cmd = "$cmd $testPath"
    
    # Add coverage options
    $cmd = "$cmd --cov=app --cov-report=term-missing --cov-fail-under=$Coverage"
    
    if ($Report) {
        $cmd = "$cmd --cov-report=html"
    }
    
    # Add verbosity
    if ($Verbose) {
        $cmd = "$cmd -v"
    } else {
        $cmd = "$cmd --tb=short"
    }
    
    # Add parallel execution
    if ($Parallel) {
        $cmd = "$cmd -n auto"
    }
    
    # Add fail-fast
    if ($FailFast) {
        $cmd = "$cmd --maxfail=1"
    } else {
        $cmd = "$cmd --maxfail=5"
    }
    
    # Add test markers
    switch ($Type) {
        "unit" { $cmd = "$cmd -m unit" }
        "integration" { $cmd = "$cmd -m integration" }
        "security" { $cmd = "$cmd -m security" }
        "performance" { $cmd = "$cmd -m performance" }
    }
    
    return $cmd
}

# Function to run tests
function Invoke-Tests {
    Write-Test "Running $Type tests..."
    
    $testCmd = Get-TestCommand
    $exitCode = 0
    
    Write-Status "Test command: $testCmd"
    
    if ($Docker) {
        # Run tests in Docker container
        $dockerCmd = "docker-compose -f docker-compose.test.yml run --rm permiso-test powershell -Command `"$testCmd`""
        Invoke-Expression $dockerCmd
        $exitCode = $LASTEXITCODE
    } else {
        # Run tests locally with Poetry
        $poetryCmd = "poetry run $testCmd"
        Invoke-Expression $poetryCmd
        $exitCode = $LASTEXITCODE
    }
    
    if ($exitCode -eq 0) {
        Write-Success "All tests passed!"
    } else {
        Write-Error "Tests failed with exit code $exitCode"
    }
    
    return $exitCode
}

# Function to generate test report
function New-TestReport {
    if ($Report) {
        Write-Status "Generating test report..."
        
        $reportDir = "test-reports"
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        
        if (-not (Test-Path $reportDir)) {
            New-Item -ItemType Directory -Path $reportDir | Out-Null
        }
        
        # Copy coverage report
        if (Test-Path "htmlcov") {
            $coverageDir = "$reportDir/coverage_$timestamp"
            Copy-Item -Recurse "htmlcov" $coverageDir
            Write-Success "Coverage report generated: $coverageDir/index.html"
        }
        
        # Generate test summary
        $summaryFile = "$reportDir/test_summary_$timestamp.txt"
        $testResult = if ($global:TestExitCode -eq 0) { "✅ PASSED" } else { "❌ FAILED" }
        
        @"
permiso Authentication System - Test Report
Generated: $(Get-Date)
Test Type: $Type
Coverage Threshold: $Coverage%
Parallel Execution: $Parallel
Docker Mode: $Docker

Test Results:
$testResult

For detailed coverage report, open: $coverageDir/index.html
"@ | Out-File -FilePath $summaryFile -Encoding UTF8
        
        Write-Success "Test summary generated: $summaryFile"
    }
}

# Function to cleanup
function Invoke-Cleanup {
    if (-not $NoCleanup) {
        Write-Status "Cleaning up test environment..."
        
        if ($Docker) {
            # Stop and remove test containers
            docker-compose -f docker-compose.test.yml down
        }
        
        Write-Success "Cleanup completed"
    }
}

# Function to handle script interruption
function Stop-TestExecution {
    Write-Warning "Test execution interrupted"
    Invoke-Cleanup
    exit 130
}

# Main execution
function Main {
    if ($Help) {
        Show-Usage
        exit 0
    }
    
    Write-Status "Starting permiso Authentication System test execution..."
    Write-Status "Test type: $Type"
    Write-Status "Coverage threshold: $Coverage%"
    Write-Status "Docker mode: $Docker"
    
    Test-Prerequisites
    Initialize-TestEnvironment
    Invoke-Migrations
    
    $global:TestExitCode = Invoke-Tests
    
    New-TestReport
    Invoke-Cleanup
    
    if ($global:TestExitCode -eq 0) {
        Write-Success "Test execution completed successfully!"
        exit 0
    } else {
        Write-Error "Test execution failed!"
        exit $global:TestExitCode
    }
}

# Error handling
trap {
    Write-Error "An error occurred: $_"
    Invoke-Cleanup
    exit 1
}

# Handle Ctrl+C
$null = Register-EngineEvent PowerShell.Exiting -Action { Stop-TestExecution }

# Run main function
Main