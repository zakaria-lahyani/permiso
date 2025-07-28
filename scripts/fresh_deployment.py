#!/usr/bin/env python3
"""
Fresh deployment script for Permiso with consolidated migration.

This script handles a complete fresh deployment:
1. Stops and removes existing containers
2. Builds new containers with the consolidated migration
3. Starts the services in the correct order
4. Runs the migration
5. Initializes default data
6. Verifies the deployment

Usage:
    python scripts/fresh_deployment.py --help
    python scripts/fresh_deployment.py --admin-password "SecurePassword123"
"""

import asyncio
import argparse
import logging
import subprocess
import sys
import time
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('fresh_deployment.log', mode='w')
    ]
)
logger = logging.getLogger(__name__)


class FreshDeployment:
    """Handles fresh deployment of Permiso with consolidated migration."""
    
    def __init__(self, admin_password: str, dry_run: bool = False):
        self.admin_password = admin_password
        self.dry_run = dry_run
        self.project_root = Path(__file__).parent.parent
    
    def run_command(self, cmd: list, description: str, check: bool = True) -> subprocess.CompletedProcess:
        """Run a command with logging."""
        logger.info(f"🔄 {description}")
        logger.info(f"   Command: {' '.join(cmd)}")
        
        if self.dry_run:
            logger.info(f"   🔍 [DRY RUN] Would run: {' '.join(cmd)}")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                check=check
            )
            
            if result.stdout:
                logger.info(f"   Output: {result.stdout.strip()}")
            if result.stderr and result.returncode == 0:
                logger.info(f"   Info: {result.stderr.strip()}")
            
            logger.info(f"   ✅ {description} completed successfully")
            return result
            
        except subprocess.CalledProcessError as e:
            logger.error(f"   ❌ {description} failed")
            logger.error(f"   Exit code: {e.returncode}")
            if e.stdout:
                logger.error(f"   Stdout: {e.stdout}")
            if e.stderr:
                logger.error(f"   Stderr: {e.stderr}")
            raise
    
    def cleanup_existing_deployment(self):
        """Stop and remove existing containers and volumes."""
        logger.info("🧹 Cleaning up existing deployment...")
        
        # Stop and remove containers
        try:
            self.run_command(
                ["python", "scripts/deploy.py", "down", "production"],
                "Stopping existing containers",
                check=False
            )
        except subprocess.CalledProcessError:
            logger.warning("   ⚠️ No existing deployment to stop")
        
        # Remove volumes (optional - comment out to preserve data)
        try:
            self.run_command(
                ["docker", "volume", "rm", "permiso_postgres_prod_data", "permiso_redis_prod_data"],
                "Removing old volumes",
                check=False
            )
        except subprocess.CalledProcessError:
            logger.warning("   ⚠️ No volumes to remove")
        
        # Remove any orphaned containers
        try:
            self.run_command(
                ["docker", "container", "prune", "-f"],
                "Removing orphaned containers",
                check=False
            )
        except subprocess.CalledProcessError:
            pass
    
    def copy_migration_to_container_context(self):
        """Ensure the new migration is available for the build."""
        logger.info("📁 Preparing migration files...")
        
        # The migration file should already be in alembic/versions/
        migration_file = self.project_root / "alembic" / "versions" / "001_create_complete_schema.py"
        
        if not migration_file.exists():
            logger.error(f"❌ Migration file not found: {migration_file}")
            raise FileNotFoundError(f"Migration file not found: {migration_file}")
        
        logger.info(f"   ✅ Migration file found: {migration_file}")
        
        # Remove old migration files to avoid conflicts
        old_migrations = [
            "001_create_base_tables.py",
            "002_create_association_tables.py",
            "003_create_service_client_tables.py", 
            "004_add_user_sessions_table.py",
            "005_fix_refresh_token_schema.py"
        ]
        
        for old_migration in old_migrations:
            old_file = self.project_root / "alembic" / "versions" / old_migration
            if old_file.exists():
                if not self.dry_run:
                    old_file.unlink()
                    logger.info(f"   🗑️ Removed old migration: {old_migration}")
                else:
                    logger.info(f"   🔍 [DRY RUN] Would remove: {old_migration}")
    
    def build_containers(self):
        """Build containers with no cache to ensure fresh build."""
        logger.info("🏗️ Building containers...")
        
        self.run_command(
            ["python", "scripts/deploy.py", "build", "production", "--no-cache"],
            "Building production containers"
        )
    
    def start_infrastructure(self):
        """Start database and redis first."""
        logger.info("🚀 Starting infrastructure services...")
        
        self.run_command(
            ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.prod.yml", 
             "up", "-d", "postgres", "redis"],
            "Starting PostgreSQL and Redis"
        )
        
        # Wait for services to be healthy
        logger.info("⏳ Waiting for infrastructure to be ready...")
        if not self.dry_run:
            time.sleep(30)  # Give services time to start
        
        # Check health
        self.run_command(
            ["docker", "ps", "--filter", "name=permiso-postgres-prod"],
            "Checking PostgreSQL status"
        )
        
        self.run_command(
            ["docker", "ps", "--filter", "name=permiso-redis-prod"],
            "Checking Redis status"
        )
    
    def run_migrations(self):
        """Run database migrations."""
        logger.info("🔄 Running database migrations...")
        
        # Start migration container
        self.run_command(
            ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.prod.yml",
             "up", "--no-deps", "migrate"],
            "Running database migrations"
        )
        
        # Check migration logs
        try:
            self.run_command(
                ["docker", "logs", "permiso-migrate-prod"],
                "Checking migration logs",
                check=False
            )
        except subprocess.CalledProcessError:
            pass
    
    def start_application(self):
        """Start the application services."""
        logger.info("🚀 Starting application services...")
        
        self.run_command(
            ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.prod.yml",
             "up", "-d", "app", "nginx"],
            "Starting application and nginx"
        )
        
        # Wait for application to be ready
        logger.info("⏳ Waiting for application to be ready...")
        if not self.dry_run:
            time.sleep(20)
    
    def initialize_data(self):
        """Initialize default data."""
        logger.info("📊 Initializing default data...")
        
        # Get the app container name (it might be different due to replicas)
        result = self.run_command(
            ["docker", "ps", "--filter", "ancestor=permiso-app", "--format", "{{.Names}}"],
            "Finding app container",
            check=False
        )
        
        if result.stdout.strip():
            app_container = result.stdout.strip().split('\n')[0]  # Get first container
            logger.info(f"   Using app container: {app_container}")
            
            # Copy the initialization script to the container
            self.run_command(
                ["docker", "cp", "scripts/init_database.py", f"{app_container}:/app/scripts/"],
                "Copying initialization script"
            )
            
            # Run initialization
            self.run_command(
                ["docker", "exec", app_container, "python", "scripts/init_database.py", 
                 "--password", self.admin_password],
                "Initializing default data"
            )
        else:
            logger.error("❌ Could not find app container")
            raise RuntimeError("App container not found")
    
    def verify_deployment(self):
        """Verify the deployment is working."""
        logger.info("✅ Verifying deployment...")
        
        # Check all containers are running
        self.run_command(
            ["docker", "ps", "--filter", "name=permiso"],
            "Checking all containers"
        )
        
        # Check database tables
        self.run_command(
            ["docker", "exec", "permiso-postgres-prod", "psql", "-U", "permiso", "-d", "permiso", "-c", "\\dt"],
            "Checking database tables"
        )
        
        # Check alembic version
        result = self.run_command(
            ["docker", "ps", "--filter", "ancestor=permiso-app", "--format", "{{.Names}}"],
            "Finding app container for verification",
            check=False
        )
        
        if result.stdout.strip():
            app_container = result.stdout.strip().split('\n')[0]
            self.run_command(
                ["docker", "exec", app_container, "alembic", "current"],
                "Checking migration status"
            )
        
        logger.info("🎉 Deployment verification completed!")
    
    def run_fresh_deployment(self):
        """Run the complete fresh deployment process."""
        logger.info("🚀 Starting fresh deployment of Permiso...")
        logger.info(f"   Admin password: {'Provided' if self.admin_password else 'Not provided'}")
        logger.info(f"   Dry run: {self.dry_run}")
        
        try:
            # Step 1: Cleanup
            self.cleanup_existing_deployment()
            
            # Step 2: Prepare migration files
            self.copy_migration_to_container_context()
            
            # Step 3: Build containers
            self.build_containers()
            
            # Step 4: Start infrastructure
            self.start_infrastructure()
            
            # Step 5: Run migrations
            self.run_migrations()
            
            # Step 6: Start application
            self.start_application()
            
            # Step 7: Initialize data
            if self.admin_password:
                self.initialize_data()
            else:
                logger.warning("⚠️ No admin password provided - skipping data initialization")
            
            # Step 8: Verify deployment
            self.verify_deployment()
            
            logger.info("🎉 Fresh deployment completed successfully!")
            logger.info("🔗 Application should be available at:")
            logger.info("   - HTTP: http://localhost")
            logger.info("   - HTTPS: https://localhost")
            
            if self.admin_password:
                logger.info("👤 Admin credentials:")
                logger.info(f"   Username: admin")
                logger.info(f"   Password: {self.admin_password}")
            
            return True
            
        except Exception as e:
            logger.error(f"💥 Fresh deployment failed: {e}")
            logger.error("📋 To debug, check:")
            logger.error("   - docker logs permiso-postgres-prod")
            logger.error("   - docker logs permiso-migrate-prod")
            logger.error("   - docker logs permiso-redis-prod")
            logger.error("   - docker ps")
            return False


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Fresh deployment of Permiso with consolidated migration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/fresh_deployment.py --admin-password "SecurePassword123"
  python scripts/fresh_deployment.py --dry-run --admin-password "TestPassword"
        """
    )
    
    parser.add_argument(
        '--admin-password',
        type=str,
        required=True,
        help='Password for the admin user'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    
    parser.add_argument(
        '--log-level',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Validate password
    if len(args.admin_password) < 8:
        logger.error("❌ Admin password must be at least 8 characters long")
        return 1
    
    # Run deployment
    try:
        deployment = FreshDeployment(
            admin_password=args.admin_password,
            dry_run=args.dry_run
        )
        
        success = deployment.run_fresh_deployment()
        return 0 if success else 1
        
    except KeyboardInterrupt:
        logger.info("⏹️ Deployment cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"💥 Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())