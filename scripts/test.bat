@echo off
REM Test runner script for Keystone Authentication System (Windows)

setlocal enabledelayedexpansion

REM Function to print colored output (limited in batch)
:print_status
echo [INFO] %~1
goto :eof

:print_success
echo [SUCCESS] %~1
goto :eof

:print_error
echo [ERROR] %~1
goto :eof

REM Function to check if Docker is running
:check_docker
docker info >nul 2>&1
if errorlevel 1 (
    call :print_error "Docker is not running. Please start Docker and try again."
    exit /b 1
)
goto :eof

REM Function to wait for services to be healthy
:wait_for_services
call :print_status "Waiting for services to be healthy..."
set /a max_attempts=30
set /a attempt=1

:wait_loop
if !attempt! gtr !max_attempts! (
    call :print_error "Services failed to become healthy within timeout"
    docker-compose ps
    exit /b 1
)

docker-compose ps | findstr "healthy" >nul
if not errorlevel 1 (
    call :print_success "Services are healthy!"
    goto :eof
)

call :print_status "Attempt !attempt!/!max_attempts! - Services not ready yet..."
timeout /t 2 /nobreak >nul
set /a attempt+=1
goto wait_loop

REM Function to run specific test types
:run_tests
set test_type=%~1
if "%test_type%"=="" set test_type=all

call :print_status "Running %test_type% tests..."

if "%test_type%"=="unit" (
    docker-compose exec keystone-dev poetry run pytest tests/test_app/ -m unit -v --tb=short
) else if "%test_type%"=="integration" (
    docker-compose exec keystone-dev poetry run pytest tests/integration/ -m integration -v --tb=short
) else if "%test_type%"=="security" (
    docker-compose exec keystone-dev poetry run pytest tests/security/ -m security -v --tb=short
) else if "%test_type%"=="fast" (
    docker-compose exec keystone-dev poetry run pytest -m "not slow" -v --tb=short
) else if "%test_type%"=="coverage" (
    docker-compose exec keystone-dev poetry run pytest --cov=app --cov-report=html --cov-report=term --cov-report=xml --cov-fail-under=80
) else if "%test_type%"=="all" (
    docker-compose exec keystone-dev poetry run pytest --cov=app --cov-report=html --cov-report=term -v
) else (
    call :print_error "Unknown test type: %test_type%"
    echo Available options: unit, integration, security, fast, coverage, all
    exit /b 1
)
goto :eof

REM Function to run tests in dedicated test container
:run_tests_container
call :print_status "Running tests in dedicated test container..."
docker-compose --profile test up --build keystone-test
goto :eof

REM Function to setup development environment
:setup_dev
call :print_status "Setting up development environment..."

REM Start services
docker-compose up -d postgres redis postgres-test redis-test

REM Wait for services
call :wait_for_services

REM Build and start dev container
docker-compose up -d keystone-dev

REM Run database migrations
call :print_status "Running database migrations..."
docker-compose exec keystone-dev poetry run alembic upgrade head

call :print_success "Development environment is ready!"
call :print_status "You can now run: docker-compose exec keystone-dev bash"
goto :eof

REM Function to cleanup
:cleanup
call :print_status "Cleaning up..."
docker-compose down -v
docker system prune -f
call :print_success "Cleanup completed!"
goto :eof

REM Function to show logs
:show_logs
set service=%~1
if "%service%"=="" (
    docker-compose logs -f
) else (
    docker-compose logs -f %service%
)
goto :eof

REM Function to test imports
:test_imports
call :print_status "Testing imports..."
docker-compose exec keystone-dev poetry run python tests/test_import.py
goto :eof

REM Function to run specific test file
:run_test_file
set test_file=%~1
if "%test_file%"=="" (
    call :print_error "Please specify a test file"
    exit /b 1
)

call :print_status "Running test file: %test_file%"
docker-compose exec keystone-dev poetry run pytest "%test_file%" -v
goto :eof

REM Main script logic
call :check_docker

set command=%~1
if "%command%"=="" set command=help

if "%command%"=="setup" (
    call :setup_dev
) else if "%command%"=="test" (
    call :run_tests %~2
) else if "%command%"=="test-container" (
    call :run_tests_container
) else if "%command%"=="imports" (
    call :test_imports
) else if "%command%"=="file" (
    call :run_test_file %~2
) else if "%command%"=="logs" (
    call :show_logs %~2
) else if "%command%"=="cleanup" (
    call :cleanup
) else (
    echo Keystone Test Runner
    echo.
    echo Usage: %0 ^<command^> [options]
    echo.
    echo Commands:
    echo   setup              Set up development environment
    echo   test [type]        Run tests (unit^|integration^|security^|fast^|coverage^|all)
    echo   test-container     Run tests in dedicated container
    echo   imports            Test import functionality
    echo   file ^<path^>        Run specific test file
    echo   logs [service]     Show logs for service or all services
    echo   cleanup            Clean up containers and volumes
    echo   help               Show this help message
    echo.
    echo Examples:
    echo   %0 setup
    echo   %0 test unit
    echo   %0 test coverage
    echo   %0 file tests/test_app/test_models/test_user.py
    echo   %0 logs keystone-dev
)

endlocal