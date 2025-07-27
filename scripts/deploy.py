#!/usr/bin/env python3
"""
Cross-platform deployment script for Permiso Authentication System
Supports Windows, Linux, and macOS with unified commands for all environments
"""

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional


class Colors:
    """ANSI color codes for cross-platform colored output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

    @classmethod
    def disable_on_windows(cls):
        """Disable colors on Windows if not supported"""
        if platform.system() == 'Windows' and not os.environ.get('ANSICON'):
            for attr in dir(cls):
                if not attr.startswith('_') and attr != 'disable_on_windows':
                    setattr(cls, attr, '')


class Logger:
    """Cross-platform logger with colored output"""
    
    def __init__(self):
        Colors.disable_on_windows()
    
    def info(self, message: str):
        print(f"{Colors.BLUE}[INFO]{Colors.END} {message}")
    
    def success(self, message: str):
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}")
    
    def warning(self, message: str):
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} {message}")
    
    def error(self, message: str):
        print(f"{Colors.RED}[ERROR]{Colors.END} {message}")
    
    def debug(self, message: str):
        print(f"{Colors.CYAN}[DEBUG]{Colors.END} {message}")


class DockerDeployer:
    """Cross-platform Docker deployment manager"""
    
    def __init__(self):
        self.logger = Logger()
        self.project_root = Path(__file__).parent.parent
        self.system = platform.system().lower()
        
        # Environment configurations
        self.environments = {
            'development': {
                'compose_files': ['docker-compose.yml', 'docker-compose.dev.yml'],
                'env_file': '.env.dev',
                'build_target': 'development'
            },
            'testing': {
                'compose_files': ['docker-compose.yml', 'docker-compose.test.yml'],
                'env_file': '.env.test',
                'build_target': 'testing'
            },
            'production': {
                'compose_files': ['docker-compose.yml', 'docker-compose.prod.yml'],
                'env_file': '.env.prod',
                'build_target': 'production'
            }
        }
    
    def check_prerequisites(self) -> bool:
        """Check if Docker and Docker Compose are available"""
        self.logger.info("Checking prerequisites...")
        
        # Check Docker
        try:
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True, check=True)
            self.logger.debug(f"Docker version: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.error("Docker is not installed or not in PATH")
            return False
        
        # Check Docker daemon
        try:
            subprocess.run(['docker', 'info'], 
                          capture_output=True, check=True)
        except subprocess.CalledProcessError:
            self.logger.error("Docker daemon is not running")
            return False
        
        # Check Docker Compose
        compose_cmd = self._get_compose_command()
        try:
            result = subprocess.run([*compose_cmd, '--version'], 
                                  capture_output=True, text=True, check=True)
            self.logger.debug(f"Docker Compose version: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.error("Docker Compose is not installed")
            return False
        
        # Check if we're in the right directory
        if not (self.project_root / 'pyproject.toml').exists():
            self.logger.error("Please run this script from the project root directory")
            return False
        
        self.logger.success("Prerequisites check passed")
        return True
    
    def _get_compose_command(self) -> List[str]:
        """Get the appropriate Docker Compose command for the platform"""
        # Try docker compose (newer syntax) first
        try:
            subprocess.run(['docker', 'compose', 'version'], 
                          capture_output=True, check=True)
            return ['docker', 'compose']
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fall back to docker-compose (older syntax)
            return ['docker-compose']
    
    def _build_compose_command(self, environment: str, command: List[str]) -> List[str]:
        """Build the complete Docker Compose command"""
        config = self.environments[environment]
        compose_cmd = self._get_compose_command()
        
        # Add compose files
        for compose_file in config['compose_files']:
            compose_cmd.extend(['-f', str(self.project_root / compose_file)])
        
        # Add environment file if it exists
        env_file = self.project_root / config['env_file']
        if env_file.exists():
            compose_cmd.extend(['--env-file', str(env_file)])
        
        # Add the actual command
        compose_cmd.extend(command)
        
        return compose_cmd
    
    def build(self, environment: str, no_cache: bool = False, pull: bool = False) -> bool:
        """Build Docker images for the specified environment"""
        self.logger.info(f"Building Docker images for {environment} environment...")
        
        config = self.environments[environment]
        build_cmd = ['build']
        
        if no_cache:
            build_cmd.append('--no-cache')
        
        if pull:
            build_cmd.append('--pull')
        
        # Add build arguments
        build_cmd.extend([
            '--build-arg', f'BUILD_TARGET={config["build_target"]}',
            '--build-arg', f'INSTALL_DEV={"true" if environment != "production" else "false"}'
        ])
        
        try:
            cmd = self._build_compose_command(environment, build_cmd)
            self.logger.debug(f"Executing: {' '.join(cmd)}")
            subprocess.run(cmd, cwd=self.project_root, check=True)
            self.logger.success(f"Docker images built successfully for {environment}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to build Docker images: {e}")
            return False
    
    def up(self, environment: str, detach: bool = True, build: bool = False) -> bool:
        """Start services for the specified environment"""
        self.logger.info(f"Starting services for {environment} environment...")
        
        up_cmd = ['up']
        
        if detach:
            up_cmd.append('-d')
        
        if build:
            up_cmd.append('--build')
        
        try:
            cmd = self._build_compose_command(environment, up_cmd)
            self.logger.debug(f"Executing: {' '.join(cmd)}")
            subprocess.run(cmd, cwd=self.project_root, check=True)
            self.logger.success(f"Services started successfully for {environment}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to start services: {e}")
            return False
    
    def down(self, environment: str, volumes: bool = False) -> bool:
        """Stop and remove services for the specified environment"""
        self.logger.info(f"Stopping services for {environment} environment...")
        
        down_cmd = ['down']
        
        if volumes:
            down_cmd.append('-v')
        
        try:
            cmd = self._build_compose_command(environment, down_cmd)
            self.logger.debug(f"Executing: {' '.join(cmd)}")
            subprocess.run(cmd, cwd=self.project_root, check=True)
            self.logger.success(f"Services stopped successfully for {environment}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to stop services: {e}")
            return False
    
    def test(self, environment: str = 'testing') -> bool:
        """Run tests in the specified environment"""
        self.logger.info(f"Running tests in {environment} environment...")
        
        try:
            # Start test services
            cmd = self._build_compose_command(environment, ['up', '-d', 'postgres', 'redis'])
            subprocess.run(cmd, cwd=self.project_root, check=True)
            
            # Wait for services to be ready
            self.logger.info("Waiting for services to be ready...")
            import time
            time.sleep(10)
            
            # Run tests
            cmd = self._build_compose_command(environment, ['run', '--rm', 'test-runner'])
            result = subprocess.run(cmd, cwd=self.project_root)
            
            # Stop test services
            self._build_compose_command(environment, ['down'])
            
            if result.returncode == 0:
                self.logger.success("All tests passed!")
                return True
            else:
                self.logger.error(f"Tests failed with exit code {result.returncode}")
                return False
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to run tests: {e}")
            return False
    
    def logs(self, environment: str, service: Optional[str] = None, follow: bool = False) -> bool:
        """Show logs for services"""
        self.logger.info(f"Showing logs for {environment} environment...")
        
        logs_cmd = ['logs']
        
        if follow:
            logs_cmd.append('-f')
        
        if service:
            logs_cmd.append(service)
        
        try:
            cmd = self._build_compose_command(environment, logs_cmd)
            subprocess.run(cmd, cwd=self.project_root, check=True)
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to show logs: {e}")
            return False
    
    def cleanup(self) -> bool:
        """Clean up Docker resources"""
        self.logger.info("Cleaning up Docker resources...")
        
        try:
            # Remove dangling images
            subprocess.run(['docker', 'image', 'prune', '-f'], check=True)
            
            # Remove unused containers
            subprocess.run(['docker', 'container', 'prune', '-f'], check=True)
            
            # Remove unused networks
            subprocess.run(['docker', 'network', 'prune', '-f'], check=True)
            
            self.logger.success("Docker cleanup completed")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to cleanup Docker resources: {e}")
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Cross-platform deployment script for Permiso Authentication System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Development
  python scripts/deploy.py up development
  python scripts/deploy.py build development --no-cache
  
  # Testing
  python scripts/deploy.py test
  python scripts/deploy.py up testing --build
  
  # Production
  python scripts/deploy.py build production
  python scripts/deploy.py up production --detach
  
  # Utilities
  python scripts/deploy.py logs development app --follow
  python scripts/deploy.py down development --volumes
  python scripts/deploy.py cleanup
        """
    )
    
    parser.add_argument('command', choices=['build', 'up', 'down', 'test', 'logs', 'cleanup'],
                       help='Command to execute')
    parser.add_argument('environment', nargs='?', 
                       choices=['development', 'testing', 'production'],
                       default='development',
                       help='Target environment (default: development)')
    parser.add_argument('--no-cache', action='store_true',
                       help='Build without using cache')
    parser.add_argument('--pull', action='store_true',
                       help='Always attempt to pull a newer version of the image')
    parser.add_argument('--build', action='store_true',
                       help='Build images before starting containers')
    parser.add_argument('--detach', action='store_true', default=True,
                       help='Run containers in the background')
    parser.add_argument('--volumes', action='store_true',
                       help='Remove named volumes declared in the volumes section')
    parser.add_argument('--service', type=str,
                       help='Specific service to show logs for')
    parser.add_argument('--follow', action='store_true',
                       help='Follow log output')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output')
    
    args = parser.parse_args()
    
    deployer = DockerDeployer()
    
    # Check prerequisites
    if not deployer.check_prerequisites():
        sys.exit(1)
    
    # Execute command
    success = False
    
    if args.command == 'build':
        success = deployer.build(args.environment, args.no_cache, args.pull)
    elif args.command == 'up':
        success = deployer.up(args.environment, args.detach, args.build)
    elif args.command == 'down':
        success = deployer.down(args.environment, args.volumes)
    elif args.command == 'test':
        success = deployer.test(args.environment)
    elif args.command == 'logs':
        success = deployer.logs(args.environment, args.service, args.follow)
    elif args.command == 'cleanup':
        success = deployer.cleanup()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()