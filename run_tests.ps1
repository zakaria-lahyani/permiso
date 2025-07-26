# PowerShell script to run tests with Docker containers
# Usage: .\run_tests.ps1 [pytest arguments]

param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$PytestArgs
)

Write-Host "Starting test environment..." -ForegroundColor Green
python run_tests.py @PytestArgs