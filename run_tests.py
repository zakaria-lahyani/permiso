#!/usr/bin/env python3
"""
Entry point script to simplify running tests with Docker containers.

This script handles:
1. Starting PostgreSQL and Redis test containers
2. Waiting for containers to be ready
3. Running tests with proper environment variables
4. Cleaning up containers after tests complete
"""

import os
import sys
import time
import subprocess
import signal
import argparse
from typing import Optional, List


class DockerTestRunner:
    """Manages Docker containers for testing."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.containers_started = False
        
    def log(self, message: str) -> None:
        """Log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[TEST RUNNER] {message}")
    
    def run_command(self, command: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run a command and optionally check for errors."""
        self.log(f"Running: {' '.join(command)}")
        try:
            result = subprocess.run(
                command,
                capture_output=not self.verbose,
                text=True,
                check=check
            )
            return result
        except subprocess.CalledProcessError as e:
            if self.verbose:
                print(f"Command failed with exit code {e.returncode}")
                if e.stdout:
                    print(f"STDOUT: {e.stdout}")
                if e.stderr:
                    print(f"STDERR: {e.stderr}")
            raise
    
    def check_docker(self) -> bool:
        """Check if Docker is available and running."""
        try:
            self.run_command(["docker", "--version"], check=True)
            self.run_command(["docker", "info"], check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("❌ Docker is not available or not running")
            print("Please ensure Docker is installed and running")
            return False
    
    def check_docker_compose(self) -> bool:
        """Check if Docker Compose is available."""
        try:
            self.run_command(["docker", "compose", "version"], check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("❌ Docker Compose is not available")
            print("Please ensure Docker Compose is installed")
            return False
    
    def start_test_containers(self) -> bool:
        """Start PostgreSQL and Redis test containers."""
        self.log("Starting test containers...")
        
        try:
            # Check if containers are already running
            containers_running = self.check_containers_running()
            if containers_running:
                self.log("✅ Test containers are already running!")
                return True
            
            # Try to start existing containers first
            self.log("Attempting to start existing containers...")
            start_result = self.run_command([
                "docker", "start", "keystone-postgres-test", "keystone-redis-test"
            ], check=False)
            
            if start_result.returncode == 0:
                self.log("Started existing containers")
            else:
                # If starting existing containers fails, try docker-compose
                self.log("Starting containers with docker-compose...")
                self.run_command([
                    "docker", "compose", "up", "-d",
                    "postgres-test", "redis-test"
                ])
            
            self.containers_started = True
            
            # Wait for containers to be healthy
            self.log("Waiting for containers to be ready...")
            max_wait = 60  # seconds
            wait_interval = 2  # seconds
            
            for i in range(0, max_wait, wait_interval):
                try:
                    # Check PostgreSQL
                    postgres_result = self.run_command([
                        "docker", "compose", "exec", "-T", "postgres-test",
                        "pg_isready", "-U", "keystone_test", "-d", "keystone_test"
                    ], check=False)
                    
                    # Check Redis
                    redis_result = self.run_command([
                        "docker", "compose", "exec", "-T", "redis-test",
                        "redis-cli", "ping"
                    ], check=False)
                    
                    if postgres_result.returncode == 0 and redis_result.returncode == 0:
                        self.log("✅ All containers are ready!")
                        return True
                        
                except Exception as e:
                    self.log(f"Container check failed: {e}")
                
                if i + wait_interval < max_wait:
                    self.log(f"Containers not ready yet, waiting {wait_interval}s...")
                    time.sleep(wait_interval)
            
            print("❌ Containers failed to become ready within timeout")
            return False
            
        except subprocess.CalledProcessError as e:
            # If containers already exist, try to check if they're running
            if "already in use" in str(e):
                self.log("Containers already exist, checking if they're healthy...")
                return self.check_containers_running()
            print(f"❌ Failed to start containers: {e}")
            return False
    
    def check_containers_running(self) -> bool:
        """Check if test containers are running and healthy."""
        try:
            # Check PostgreSQL
            postgres_result = self.run_command([
                "docker", "compose", "exec", "-T", "postgres-test",
                "pg_isready", "-U", "keystone_test", "-d", "keystone_test"
            ], check=False)
            
            # Check Redis
            redis_result = self.run_command([
                "docker", "compose", "exec", "-T", "redis-test",
                "redis-cli", "ping"
            ], check=False)
            
            return postgres_result.returncode == 0 and redis_result.returncode == 0
            
        except Exception as e:
            self.log(f"Error checking container health: {e}")
            return False
    
    def stop_test_containers(self) -> None:
        """Stop and remove test containers."""
        if not self.containers_started:
            return
            
        self.log("Stopping test containers...")
        try:
            self.run_command([
                "docker", "compose", "down", 
                "postgres-test", "redis-test"
            ], check=False)
            
            # Remove volumes to ensure clean state
            self.run_command([
                "docker", "compose", "down", "-v"
            ], check=False)
            
        except Exception as e:
            self.log(f"Error stopping containers: {e}")
    
    def run_tests(self, pytest_args: List[str]) -> int:
        """Run tests with proper environment variables."""
        self.log("Running tests...")
        
        # Set environment variables for test containers
        env = os.environ.copy()
        env.update({
            "TEST_DATABASE_URL": "postgresql+asyncpg://keystone_test:keystone_test_password@localhost:5433/keystone_test",
            "TEST_REDIS_URL": "redis://localhost:6380/0",
            "ENVIRONMENT": "testing",
            "PYTHONPATH": os.getcwd(),
        })
        
        # Build pytest command
        cmd = ["poetry", "run", "pytest"] + pytest_args
        
        try:
            result = subprocess.run(cmd, env=env)
            return result.returncode
        except KeyboardInterrupt:
            print("\n⚠️  Tests interrupted by user")
            return 130
        except Exception as e:
            print(f"❌ Error running tests: {e}")
            return 1
    
    def cleanup(self) -> None:
        """Clean up resources."""
        self.stop_test_containers()


def signal_handler(signum, frame, runner: DockerTestRunner):
    """Handle interrupt signals."""
    print(f"\n⚠️  Received signal {signum}, cleaning up...")
    runner.cleanup()
    sys.exit(130)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run tests with Docker containers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_tests.py                     # Run all tests
  python run_tests.py -v                  # Run with verbose output
  python run_tests.py tests/unit/         # Run only unit tests
  python run_tests.py -k test_auth        # Run tests matching pattern
  python run_tests.py --no-cov            # Run without coverage
        """
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Don't stop containers after tests (useful for debugging)"
    )
    
    parser.add_argument(
        "pytest_args",
        nargs="*",
        help="Additional arguments to pass to pytest"
    )
    
    args = parser.parse_args()
    
    # Create test runner
    runner = DockerTestRunner(verbose=args.verbose)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, lambda s, f: signal_handler(s, f, runner))
    signal.signal(signal.SIGTERM, lambda s, f: signal_handler(s, f, runner))
    
    try:
        # Check prerequisites
        if not runner.check_docker():
            return 1
        
        if not runner.check_docker_compose():
            return 1
        
        print("🚀 Starting test environment...")
        
        # Start containers
        if not runner.start_test_containers():
            return 1
        
        print("🧪 Running tests...")
        
        # Run tests
        exit_code = runner.run_tests(args.pytest_args)
        
        if exit_code == 0:
            print("✅ All tests passed!")
        else:
            print(f"❌ Tests failed with exit code {exit_code}")
        
        return exit_code
        
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user")
        return 130
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1
    finally:
        if not args.no_cleanup:
            runner.cleanup()
        else:
            print("⚠️  Containers left running (--no-cleanup specified)")


if __name__ == "__main__":
    sys.exit(main())