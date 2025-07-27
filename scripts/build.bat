@echo off
REM permiso Authentication System - Build Script (Batch)
REM Simple wrapper for PowerShell build script

setlocal enabledelayedexpansion

REM Default values
set ENVIRONMENT=development
set PUSH_FLAG=
set TEST_FLAG=
set CLEANUP_FLAG=
set HELP_FLAG=

REM Parse command line arguments
:parse_args
if "%~1"=="" goto :execute
if /i "%~1"=="-e" (
    set ENVIRONMENT=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--environment" (
    set ENVIRONMENT=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="-p" (
    set PUSH_FLAG=-Push
    shift
    goto :parse_args
)
if /i "%~1"=="--push" (
    set PUSH_FLAG=-Push
    shift
    goto :parse_args
)
if /i "%~1"=="-t" (
    set TEST_FLAG=-Test
    shift
    goto :parse_args
)
if /i "%~1"=="--test" (
    set TEST_FLAG=-Test
    shift
    goto :parse_args
)
if /i "%~1"=="-c" (
    set CLEANUP_FLAG=-Cleanup
    shift
    goto :parse_args
)
if /i "%~1"=="--cleanup" (
    set CLEANUP_FLAG=-Cleanup
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
echo Usage: scripts\build.bat [OPTIONS]
echo.
echo Build permiso Authentication System for different environments
echo.
echo OPTIONS:
echo     -e, --environment ENV    Target environment (development^|testing^|production) [default: development]
echo     -p, --push              Push image to registry after build
echo     -t, --test              Run tests after build (only for testing environment)
echo     -c, --cleanup           Clean up intermediate containers and images
echo     -h, --help              Show this help message
echo.
echo EXAMPLES:
echo     # Build for development
echo     scripts\build.bat -e development
echo.
echo     # Build for testing and run tests
echo     scripts\build.bat -e testing --test
echo.
echo     # Build for production and push to registry
echo     scripts\build.bat -e production --push
echo.
echo ENVIRONMENTS:
echo     development    - Development environment with hot reload and debug tools
echo     testing        - Testing environment with test dependencies and test runner
echo     production     - Production environment optimized for performance and security
goto :eof

:execute
if "%HELP_FLAG%"=="-Help" (
    goto :show_usage
)

echo [INFO] Starting permiso Authentication System build process...
echo [INFO] Environment: %ENVIRONMENT%

REM Check if PowerShell is available
powershell -Command "Get-Host" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] PowerShell is not available. Please install PowerShell.
    exit /b 1
)

REM Execute PowerShell script
powershell -ExecutionPolicy Bypass -File "scripts\build.ps1" -Environment %ENVIRONMENT% %PUSH_FLAG% %TEST_FLAG% %CLEANUP_FLAG%

if errorlevel 1 (
    echo [ERROR] Build failed with exit code %errorlevel%
    exit /b %errorlevel%
)

echo [SUCCESS] Build completed successfully!