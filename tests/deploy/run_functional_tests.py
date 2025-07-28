#!/usr/bin/env python3
"""
Permiso Functional Test Runner

This script runs the comprehensive functional test suite for the Permiso authentication system.
It provides various execution modes and generates detailed reports.
"""

import os
import sys
import argparse
import subprocess
import time
from pathlib import Path


def check_environment():
    """Check if the test environment is properly configured."""
    print("🔍 Checking test environment...")
    
    # Check if Docker containers are running
    required_containers = [
        "permiso-app-1",
        "permiso-postgres-prod", 
        "permiso-redis-prod",
        "permiso-nginx-prod"
    ]
    
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=True
        )
        running_containers = result.stdout.strip().split('\n')
        
        missing_containers = []
        for container in required_containers:
            if container not in running_containers:
                missing_containers.append(container)
        
        if missing_containers:
            print(f"❌ Missing containers: {', '.join(missing_containers)}")
            print("Please start all required Docker containers before running tests.")
            return False
        
        print("✅ All required Docker containers are running")
        return True
        
    except subprocess.CalledProcessError:
        print("❌ Failed to check Docker containers. Is Docker running?")
        return False
    except FileNotFoundError:
        print("❌ Docker command not found. Please install Docker.")
        return False


def install_dependencies():
    """Install test dependencies."""
    print("📦 Installing test dependencies...")
    
    try:
        subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ], check=True)
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        return False


def run_tests(test_type="all", verbose=False, html_report=False, json_report=False):
    """Run the functional tests."""
    print(f"🧪 Running {test_type} functional tests...")
    
    # Base pytest command
    cmd = [sys.executable, "-m", "pytest"]
    
    # Add verbosity
    if verbose:
        cmd.append("-v")
    else:
        cmd.append("-q")
    
    # Add test selection based on type
    if test_type == "auth":
        cmd.append("test_authentication_flows.py")
    elif test_type == "users":
        cmd.append("test_user_management.py")
    elif test_type == "happy":
        cmd.append("scenarios/happy_path.py")
    elif test_type == "errors":
        cmd.append("scenarios/error_handling.py")
    elif test_type == "edge":
        cmd.append("scenarios/edge_cases.py")
    elif test_type == "scenarios":
        cmd.append("scenarios/")
    elif test_type == "all":
        cmd.extend([
            "test_authentication_flows.py",
            "test_user_management.py", 
            "scenarios/"
        ])
    
    # Add reporting options
    if html_report:
        cmd.extend(["--html=reports/functional_test_report.html", "--self-contained-html"])
    
    if json_report:
        cmd.extend(["--json-report", "--json-report-file=reports/functional_test_report.json"])
    
    # Add timeout
    cmd.extend(["--timeout=300"])
    
    # Create reports directory
    os.makedirs("reports", exist_ok=True)
    
    # Run tests
    start_time = time.time()
    try:
        result = subprocess.run(cmd, check=False)
        end_time = time.time()
        
        duration = end_time - start_time
        print(f"⏱️  Test execution completed in {duration:.2f} seconds")
        
        if result.returncode == 0:
            print("✅ All tests passed!")
        else:
            print(f"❌ Some tests failed (exit code: {result.returncode})")
        
        return result.returncode == 0
        
    except KeyboardInterrupt:
        print("\n⚠️  Test execution interrupted by user")
        return False
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        return False


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Run Permiso functional tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Test Types:
  all       - Run all functional tests (default)
  auth      - Run authentication flow tests only
  users     - Run user management tests only
  happy     - Run happy path scenarios only
  errors    - Run error handling scenarios only
  edge      - Run edge case scenarios only
  scenarios - Run all scenario tests only

Examples:
  python run_functional_tests.py                    # Run all tests
  python run_functional_tests.py --type auth -v     # Run auth tests with verbose output
  python run_functional_tests.py --html --json      # Run all tests with HTML and JSON reports
  python run_functional_tests.py --no-env-check     # Skip environment check
        """
    )
    
    parser.add_argument(
        "--type", "-t",
        choices=["all", "auth", "users", "happy", "errors", "edge", "scenarios"],
        default="all",
        help="Type of tests to run (default: all)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate HTML test report"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Generate JSON test report"
    )
    
    parser.add_argument(
        "--no-env-check",
        action="store_true",
        help="Skip environment check"
    )
    
    parser.add_argument(
        "--no-install",
        action="store_true",
        help="Skip dependency installation"
    )
    
    args = parser.parse_args()
    
    print("🚀 Permiso Functional Test Runner")
    print("=" * 50)
    
    # Change to test directory
    test_dir = Path(__file__).parent
    os.chdir(test_dir)
    
    # Check environment
    if not args.no_env_check:
        if not check_environment():
            sys.exit(1)
    
    # Install dependencies
    if not args.no_install:
        if not install_dependencies():
            sys.exit(1)
    
    # Run tests
    success = run_tests(
        test_type=args.type,
        verbose=args.verbose,
        html_report=args.html,
        json_report=args.json
    )
    
    print("=" * 50)
    if success:
        print("🎉 Functional test execution completed successfully!")
        if args.html:
            print("📊 HTML report: reports/functional_test_report.html")
        if args.json:
            print("📊 JSON report: reports/functional_test_report.json")
    else:
        print("💥 Functional test execution failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()