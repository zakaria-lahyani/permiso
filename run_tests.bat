@echo off
REM Windows batch script to run tests with Docker containers
REM Usage: run_tests.bat [pytest arguments]

echo Starting test environment...
python run_tests.py %*