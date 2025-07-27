# PowerShell script for automated testing with Docker containers
param(
    [string]$TestPath = "",
    [switch]$Verbose,
    [switch]$NoCoverage,
    [switch]$KeepContainers = $true,  # Default to keeping containers for debugging
    [switch]$RebuildImages,
    [switch]$Interactive  # New parameter for interactive debugging
)

$ErrorActionPreference = "Stop"
$TestReportsDir = "test-reports"
$CoverageReportsDir = "htmlcov"

function Write-Step {
    param([string]$Message)
    Write-Host "[STEP] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Test-DockerAvailable {
    Write-Step "Checking Docker availability..."
    try {
        $dockerVersion = docker --version 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "Docker command failed"
        }
        Write-Success "Docker is available: $dockerVersion"
        
        $composeVersion = docker compose version 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "Docker Compose command failed"
        }
        Write-Success "Docker Compose is available: $composeVersion"
        return $true
    }
    catch {
        Write-Error "Docker is not available or not running"
        return $false
    }
}

function Stop-ExistingContainers {
    Write-Step "Stopping existing containers..."
    try {
        docker compose down --remove-orphans 2>$null
        Write-Success "Existing containers stopped"
    }
    catch {
        Write-Warning "No existing containers to stop"
    }
}

function Build-Images {
    param([bool]$Force = $false)
    
    if ($Force) {
        Write-Step "Rebuilding Docker images..."
        docker compose build --no-cache keystone-test
    } else {
        Write-Step "Building Docker images..."
        docker compose build keystone-test
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to build Docker images"
        exit 1
    }
    Write-Success "Docker images built successfully"
}

function Start-Infrastructure {
    Write-Step "Starting infrastructure containers..."
    
    docker compose up -d postgres-test redis-test
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to start infrastructure containers"
        exit 1
    }
    
    Write-Step "Waiting for infrastructure to be ready..."
    $maxAttempts = 30
    $attempt = 0
    
    do {
        $attempt++
        Start-Sleep -Seconds 2
        
        $pgReady = docker compose exec -T postgres-test pg_isready -U keystone_test -d keystone_test 2>$null
        $pgHealthy = $LASTEXITCODE -eq 0
        
        $redisReady = docker compose exec -T redis-test redis-cli ping 2>$null
        $redisHealthy = $LASTEXITCODE -eq 0
        
        if ($pgHealthy -and $redisHealthy) {
            Write-Success "Infrastructure is ready!"
            return $true
        }
        
        if ($Verbose) {
            $pgStatus = if($pgHealthy){"OK"}else{"FAIL"}
            $redisStatus = if($redisHealthy){"OK"}else{"FAIL"}
            Write-Host "Attempt $attempt/$maxAttempts - PostgreSQL: $pgStatus Redis: $redisStatus"
        }
        
    } while ($attempt -lt $maxAttempts)
    
    Write-Error "Infrastructure failed to become ready within timeout"
    return $false
}

function Prepare-TestEnvironment {
    Write-Step "Preparing test environment..."
    
    if (!(Test-Path $TestReportsDir)) {
        New-Item -ItemType Directory -Path $TestReportsDir -Force | Out-Null
    }
    if (!(Test-Path $CoverageReportsDir)) {
        New-Item -ItemType Directory -Path $CoverageReportsDir -Force | Out-Null
    }
    
    Write-Success "Test environment prepared"
}

function Run-Tests {
    param(
        [string]$TestPath,
        [bool]$WithCoverage = $true,
        [bool]$Verbose = $false,
        [bool]$Interactive = $false
    )
    
    if ($Interactive) {
        Write-Step "Starting interactive debugging session..."
        Write-Host "Container will stay running. Use 'docker compose exec keystone-test bash' to connect." -ForegroundColor Yellow
        Write-Host "Test script is available at /app/run_tests.sh" -ForegroundColor Yellow
        Write-Host "Press Ctrl+C to exit when done debugging." -ForegroundColor Yellow
        
        # Start the test container and keep it running
        docker compose up -d keystone-test
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to start test container"
            return 1
        }
        
        # Wait for user to finish debugging
        try {
            while ($true) {
                Start-Sleep -Seconds 5
                $containerStatus = docker compose ps keystone-test --format json | ConvertFrom-Json
                if (-not $containerStatus -or $containerStatus.State -ne "running") {
                    Write-Warning "Test container stopped"
                    break
                }
            }
        }
        catch {
            Write-Host "Exiting interactive mode..." -ForegroundColor Yellow
        }
        
        return 0
    }
    
    Write-Step "Running tests in containerized environment..."
    
    $pytestArgs = @()
    
    if ($TestPath) {
        $pytestArgs += $TestPath
    }
    
    if ($WithCoverage) {
        $pytestArgs += @(
            "--cov=app",
            "--cov-report=html:/app/htmlcov",
            "--cov-report=term-missing",
            "--cov-report=xml:/app/test-reports/coverage.xml"
        )
    }
    
    $pytestArgs += @(
        "--junitxml=/app/test-reports/junit.xml",
        "-v"
    )
    
    if ($Verbose) {
        $pytestArgs += "-s"
    }
    
    $testCommand = "/app/run_tests.sh " + ($pytestArgs -join " ")
    
    Write-Host "Executing: $testCommand" -ForegroundColor Cyan
    
    docker compose run --rm `
        -e ENVIRONMENT=testing `
        -e TEST_DATABASE_URL="postgresql+asyncpg://keystone_test:keystone_test_password@postgres-test:5432/keystone_test" `
        -e TEST_REDIS_URL="redis://redis-test:6379/0" `
        -e PYTHONPATH=/app `
        keystone-test sh -c $testCommand
    
    $testExitCode = $LASTEXITCODE
    
    if ($testExitCode -eq 0) {
        Write-Success "All tests passed!"
    } else {
        Write-Error "Tests failed with exit code: $testExitCode"
    }
    
    return $testExitCode
}

function Show-TestResults {
    Write-Step "Test results summary:"
    
    $junitFile = Join-Path $TestReportsDir "junit.xml"
    if (Test-Path $junitFile) {
        try {
            [xml]$junit = Get-Content $junitFile
            $testSuite = $junit.testsuite
            if ($testSuite) {
                Write-Host "Test Results:" -ForegroundColor Blue
                Write-Host "   Tests: $($testSuite.tests)" -ForegroundColor Blue
                Write-Host "   Failures: $($testSuite.failures)" -ForegroundColor $(if($testSuite.failures -eq "0") {"Green"} else {"Red"})
                Write-Host "   Errors: $($testSuite.errors)" -ForegroundColor $(if($testSuite.errors -eq "0") {"Green"} else {"Red"})
                Write-Host "   Time: $($testSuite.time)s" -ForegroundColor Blue
            }
        }
        catch {
            Write-Warning "Could not parse JUnit results"
        }
    }
    
    $coverageFile = Join-Path $TestReportsDir "coverage.xml"
    if (Test-Path $coverageFile) {
        try {
            [xml]$coverage = Get-Content $coverageFile
            $coverageRate = [math]::Round([double]$coverage.coverage.'line-rate' * 100, 2)
            Write-Host "Coverage: $coverageRate%" -ForegroundColor $(if($coverageRate -ge 80) {"Green"} else {"Yellow"})
        }
        catch {
            Write-Warning "Could not parse coverage results"
        }
    }
    
    Write-Host "Reports available at:" -ForegroundColor Blue
    if (Test-Path $TestReportsDir) {
        Write-Host "   JUnit: $TestReportsDir/junit.xml" -ForegroundColor Blue
        Write-Host "   Coverage XML: $TestReportsDir/coverage.xml" -ForegroundColor Blue
    }
    if (Test-Path $CoverageReportsDir) {
        Write-Host "   Coverage HTML: $CoverageReportsDir/index.html" -ForegroundColor Blue
    }
}

function Cleanup-Containers {
    param([bool]$KeepRunning = $false)
    
    if ($KeepRunning) {
        Write-Warning "Keeping containers running (-KeepContainers specified)"
        Write-Host "To stop containers later, run: docker compose down" -ForegroundColor Yellow
    } else {
        Write-Step "Cleaning up containers..."
        docker compose down --remove-orphans
        Write-Success "Containers cleaned up"
    }
}

# Main execution
Write-Host "Keystone Authentication System - Docker Test Runner" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green

try {
    if (!(Test-DockerAvailable)) {
        exit 1
    }
    
    Stop-ExistingContainers
    Build-Images -Force $RebuildImages
    Prepare-TestEnvironment
    
    if (!(Start-Infrastructure)) {
        exit 1
    }
    
    $testResult = Run-Tests -TestPath $TestPath -WithCoverage (!$NoCoverage) -Verbose $Verbose -Interactive $Interactive
    
    if (-not $Interactive) {
        Show-TestResults
    }
    
    Cleanup-Containers -KeepRunning $KeepContainers
    
    if ($testResult -eq 0) {
        Write-Success "All tests completed successfully!"
    } else {
        Write-Error "Tests failed!"
    }
    
    exit $testResult
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Cleanup-Containers -KeepRunning $false
    exit 1
}