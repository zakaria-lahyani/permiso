@echo off
REM permiso Authentication System - Test Runner Script (Batch)
REM Simple wrapper for PowerShell test runner script

setlocal enabledelayedexpansion

REM Default values
set TEST_TYPE=all
set COVERAGE=80
set VERBOSE_FLAG=
set PARALLEL_FLAG=
set FAILFAST_FLAG=
set REPORT_FLAG=
set NOCLEANUP_FLAG=
set DOCKER_FLAG=
set HELP_FLAG=

REM Parse command line arguments
:parse_args
if "%~1"=="" goto :execute
if /i "%~1"=="-t" (
    set TEST_TYPE=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--type" (
    set TEST_TYPE=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="-c" (
    set COVERAGE=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--coverage" (
    set COVERAGE=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="-v" (
    set VERBOSE_FLAG=-Verbose
    shift
    goto :parse_args
)
if /i "%~1"=="--verbose" (
    set VERBOSE_FLAG=-Verbose
    shift
    goto :parse_args
)
if /i "%~1"=="-p" (
    set PARALLEL_FLAG=-Parallel
    shift
    goto :parse_args
)
if /i "%~1"=="--parallel" (
    set PARALLEL_FLAG=-Parallel
    shift
    goto :parse_args
)
if /i "%~1"=="-f" (
    set FAILFAST_FLAG=-FailFast
    shift
    goto :parse_args
)
if /i "%~1"=="--fail-fast" (
    set FAILFAST_FLAG=-FailFast
    shift
    goto :parse_args
)
if /i "%~1"=="-r" (
    set REPORT_FLAG=-Report
    shift
    goto :parse_args
)
if /i "%~1"=="--report" (
    set REPORT_FLAG=-Report
    shift
    goto :parse_args
)
if /i "%~1"=="-n" (
    set NOCLEANUP_FLAG=-NoCleanup
    shift
    goto :parse_args
)
if /i "%~1"=="--no-cleanup" (
    set NOCLEANUP_FLAG=-NoCleanup
    shift
    goto :parse_args
)
if /i "%~1"=="-d" (
    set DOCKER_FLAG=-Docker
    shift
    goto :parse_args
)
if /i "%~1"=="--docker" (
    set DOCKER_FLAG=-Docker
    shift
    goto :parse_args
)
if /i "%~1"=="-h" (
    set HELP_FLAG=-Help
    shift
    goto :parse_args
)
if /i "%~1"=="--help" (
    set HELP_FLAG=-Help
    shift
    goto :parse_args
)
echo Unknown option: %~1
goto :show_usage

:show_usage
echo Usage: scripts\test-runner.bat [OPTIONS]
echo.
echo Run tests for permiso Authentication System with Poetry
echo.
echo OPTIONS:
echo     -t, --type TYPE         Test type (all^|unit^|integration^|security^|api^|performance) [default: all]
echo     -c, --coverage NUM      Coverage threshold percentage [default: 80]
echo     -v, --verbose           Enable verbose output
echo     -p, --parallel          Run tests in parallel
echo     -f, --fail-fast         Stop on first failure
echo     -r, --report            Generate HTML coverage report
echo     -n, --no-cleanup        Don't cleanup after tests
echo     -d, --docker            Run tests in Docker container
echo     -h, --help              Show this help message
echo.
echo TEST TYPES:
echo     all            - Run all test suites
echo     unit           - Run unit tests only
echo     integration    - Run integration tests only
echo     security       - Run security tests only
echo     api            - Run API tests only
echo     performance    - Run performance tests only
echo.
echo EXAMPLES:
echo     # Run all tests with coverage
echo     scripts\test-runner.bat
echo.
echo     # Run only unit tests with verbose output
echo     scripts\test-runner.bat --type unit --verbose
echo.
echo     # Run tests in parallel with HTML report
echo     scripts\test-runner.bat --parallel --report
echo.
echo     # Run security tests with fail-fast
echo     scripts\test-runner.bat --type security --fail-fast
echo.
echo     # Run tests in Docker container
echo     scripts\test-runner.bat --docker
goto :eof

:execute
if "%HELP_FLAG%"=="-Help" (
    goto :show_usage
)

echo [INFO] Starting permiso Authentication System test execution...
echo [INFO] Test type: %TEST_TYPE%
echo [INFO] Coverage threshold: %COVERAGE%%%

REM Check if PowerShell is available
powershell -Command "Get-Host" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] PowerShell is not available. Please install PowerShell.
    exit /b 1
)

REM Execute PowerShell script
powershell -ExecutionPolicy Bypass -File "scripts\test-runner.ps1" -Type %TEST_TYPE% -Coverage %COVERAGE% %VERBOSE_FLAG% %PARALLEL_FLAG% %FAILFAST_FLAG% %REPORT_FLAG% %NOCLEANUP_FLAG% %DOCKER_FLAG%

if errorlevel 1 (
    echo [ERROR] Test execution failed with exit code %errorlevel%
    exit /b %errorlevel%
)

echo [SUCCESS] Test execution completed successfully!