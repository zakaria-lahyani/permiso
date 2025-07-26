"""Test runner script for Keystone authentication system."""

import asyncio
import sys
import subprocess
from pathlib import Path


def run_unit_tests():
    """Run unit tests."""
    print("🧪 Running unit tests...")
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        "tests/unit/", 
        "-v", 
        "--tb=short",
        "--cov=app",
        "--cov-report=term-missing",
        "-m", "unit"
    ], capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    return result.returncode == 0


def run_integration_tests():
    """Run integration tests."""
    print("🔗 Running integration tests...")
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        "tests/integration/", 
        "-v", 
        "--tb=short",
        "-m", "integration"
    ], capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    return result.returncode == 0


def run_security_tests():
    """Run security tests."""
    print("🔒 Running security tests...")
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        "tests/security/", 
        "-v", 
        "--tb=short",
        "-m", "security"
    ], capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    return result.returncode == 0


def run_all_tests():
    """Run all tests."""
    print("🚀 Running all tests...")
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        "tests/", 
        "-v", 
        "--tb=short",
        "--cov=app",
        "--cov-report=term-missing",
        "--cov-report=html",
        "--cov-fail-under=80"
    ], capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    return result.returncode == 0


def run_fast_tests():
    """Run fast tests only (exclude slow tests)."""
    print("⚡ Running fast tests...")
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        "tests/", 
        "-v", 
        "--tb=short",
        "-m", "not slow"
    ], capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    return result.returncode == 0


def check_test_coverage():
    """Check test coverage and generate report."""
    print("📊 Generating coverage report...")
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        "tests/", 
        "--cov=app",
        "--cov-report=html",
        "--cov-report=term",
        "--cov-fail-under=80",
        "--quiet"
    ], capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    coverage_dir = Path("htmlcov")
    if coverage_dir.exists():
        print(f"📈 Coverage report generated at: {coverage_dir.absolute()}/index.html")
    
    return result.returncode == 0


def main():
    """Main test runner."""
    if len(sys.argv) < 2:
        print("Usage: python tests/test_runner.py [unit|integration|security|all|fast|coverage]")
        sys.exit(1)
    
    test_type = sys.argv[1].lower()
    
    success = False
    
    if test_type == "unit":
        success = run_unit_tests()
    elif test_type == "integration":
        success = run_integration_tests()
    elif test_type == "security":
        success = run_security_tests()
    elif test_type == "all":
        success = run_all_tests()
    elif test_type == "fast":
        success = run_fast_tests()
    elif test_type == "coverage":
        success = check_test_coverage()
    else:
        print(f"Unknown test type: {test_type}")
        print("Available options: unit, integration, security, all, fast, coverage")
        sys.exit(1)
    
    if success:
        print("✅ All tests passed!")
        sys.exit(0)
    else:
        print("❌ Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()