#!/usr/bin/env python3
"""
Permiso Authentication System - Default Data Initialization Script

This script initializes the database with default roles, scopes, and optionally creates
a bootstrap admin user. It can be used for production deployment, development setup,
or testing environments.

Features:
- Creates default roles (admin, user, trader, service)
- Creates comprehensive scopes with proper resource mapping
- Assigns scopes to roles based on permission model
- Optionally creates bootstrap admin user with secure password
- Supports both direct database connection and calling SQL function
- Comprehensive logging and error handling
- Environment-aware configuration
- Dry-run mode for testing

Usage:
    python scripts/initialize_default_data.py --help
    python scripts/initialize_default_data.py --admin-password "SecurePassword123"
    python scripts/initialize_default_data.py --use-sql-function --admin-password "SecurePassword123"
    python scripts/initialize_default_data.py --dry-run
"""

import asyncio
import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime, timezone
import uuid

# Add the app directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy import text, select
    from sqlalchemy.exc import IntegrityError, SQLAlchemyError
    
    from app.config.database import AsyncSessionLocal, engine
    from app.config.settings import settings
    from app.core.password import hash_password, validate_password
    from app.models.user import User
    from app.models.role import Role
    from app.models.scope import Scope
    from app.models.associations import user_roles, role_scopes
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Make sure you're running this script from the project root directory")
    print("and that all dependencies are installed.")
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('initialization.log', mode='a')
    ]
)
logger = logging.getLogger(__name__)


class DatabaseInitializer:
    """Handles database initialization with default data."""
    
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.session: Optional[AsyncSession] = None
        
        # Default roles configuration
        self.default_roles = [
            {
                'name': 'admin',
                'description': 'Administrator role with full system access'
            },
            {
                'name': 'user',
                'description': 'Standard user role with basic permissions'
            },
            {
                'name': 'trader',
                'description': 'Trading user role with trading permissions'
            },
            {
                'name': 'service',
                'description': 'Service client role for API access'
            }
        ]
        
        # Default scopes configuration
        self.default_scopes = [
            # Admin scopes
            {
                'name': 'admin:users',
                'description': 'Manage user accounts and permissions',
                'resource': 'users'
            },
            {
                'name': 'admin:system',
                'description': 'System administration and configuration',
                'resource': 'system'
            },
            {
                'name': 'admin:clients',
                'description': 'Manage service clients and API access',
                'resource': 'clients'
            },
            # User profile scopes
            {
                'name': 'read:profile',
                'description': 'Read user profile information',
                'resource': 'profile'
            },
            {
                'name': 'write:profile',
                'description': 'Update user profile information',
                'resource': 'profile'
            },
            # Trading scopes
            {
                'name': 'read:trades',
                'description': 'Read trading data and history',
                'resource': 'trades'
            },
            {
                'name': 'write:trades',
                'description': 'Execute trades and modify trading data',
                'resource': 'trades'
            },
            # Service scopes
            {
                'name': 'service:mt5',
                'description': 'Access MT5 trading platform services',
                'resource': 'mt5'
            },
            {
                'name': 'service:api',
                'description': 'Access internal API services',
                'resource': 'api'
            }
        ]
        
        # Role-scope assignments
        self.role_scope_assignments = {
            'admin': [
                'admin:users', 'admin:system', 'admin:clients',
                'read:profile', 'write:profile'
            ],
            'user': [
                'read:profile', 'write:profile'
            ],
            'trader': [
                'read:profile', 'write:profile',
                'read:trades', 'write:trades'
            ],
            'service': [
                'service:mt5', 'service:api'
            ]
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = AsyncSessionLocal()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            if exc_type:
                await self.session.rollback()
            await self.session.close()
    
    async def check_database_connection(self) -> bool:
        """Check if database connection is working."""
        try:
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            logger.info("✅ Database connection successful")
            return True
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            return False
    
    async def check_tables_exist(self) -> bool:
        """Check if required tables exist."""
        required_tables = ['users', 'roles', 'scopes', 'user_roles', 'role_scopes']
        
        try:
            for table in required_tables:
                result = await self.session.execute(
                    text("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_name = :table_name
                        )
                    """),
                    {'table_name': table}
                )
                exists = result.scalar()
                if not exists:
                    logger.error(f"❌ Required table '{table}' does not exist")
                    return False
            
            logger.info("✅ All required tables exist")
            return True
        except Exception as e:
            logger.error(f"❌ Error checking tables: {e}")
            return False
    
    async def create_roles(self) -> Dict[str, str]:
        """Create default roles and return role name to ID mapping."""
        logger.info("Creating default roles...")
        role_ids = {}
        
        for role_config in self.default_roles:
            try:
                # Check if role already exists
                result = await self.session.execute(
                    select(Role).where(Role.name == role_config['name'])
                )
                existing_role = result.scalar_one_or_none()
                
                if existing_role:
                    logger.info(f"  ✓ Role '{role_config['name']}' already exists")
                    role_ids[role_config['name']] = str(existing_role.id)
                else:
                    if not self.dry_run:
                        new_role = Role(
                            name=role_config['name'],
                            description=role_config['description']
                        )
                        self.session.add(new_role)
                        await self.session.flush()  # Get the ID
                        role_ids[role_config['name']] = str(new_role.id)
                        logger.info(f"  ✅ Created role '{role_config['name']}'")
                    else:
                        role_ids[role_config['name']] = str(uuid.uuid4())
                        logger.info(f"  🔍 [DRY RUN] Would create role '{role_config['name']}'")
                        
            except Exception as e:
                logger.error(f"  ❌ Error creating role '{role_config['name']}': {e}")
                raise
        
        return role_ids
    
    async def create_scopes(self) -> Dict[str, str]:
        """Create default scopes and return scope name to ID mapping."""
        logger.info("Creating default scopes...")
        scope_ids = {}
        
        for scope_config in self.default_scopes:
            try:
                # Check if scope already exists
                result = await self.session.execute(
                    select(Scope).where(Scope.name == scope_config['name'])
                )
                existing_scope = result.scalar_one_or_none()
                
                if existing_scope:
                    logger.info(f"  ✓ Scope '{scope_config['name']}' already exists")
                    scope_ids[scope_config['name']] = str(existing_scope.id)
                else:
                    if not self.dry_run:
                        new_scope = Scope(
                            name=scope_config['name'],
                            description=scope_config['description'],
                            resource=scope_config['resource']
                        )
                        self.session.add(new_scope)
                        await self.session.flush()  # Get the ID
                        scope_ids[scope_config['name']] = str(new_scope.id)
                        logger.info(f"  ✅ Created scope '{scope_config['name']}'")
                    else:
                        scope_ids[scope_config['name']] = str(uuid.uuid4())
                        logger.info(f"  🔍 [DRY RUN] Would create scope '{scope_config['name']}'")
                        
            except Exception as e:
                logger.error(f"  ❌ Error creating scope '{scope_config['name']}': {e}")
                raise
        
        return scope_ids
    
    async def assign_scopes_to_roles(self, role_ids: Dict[str, str], scope_ids: Dict[str, str]):
        """Assign scopes to roles based on configuration."""
        logger.info("Assigning scopes to roles...")
        
        for role_name, scope_names in self.role_scope_assignments.items():
            if role_name not in role_ids:
                logger.warning(f"  ⚠️ Role '{role_name}' not found, skipping scope assignments")
                continue
            
            role_id = role_ids[role_name]
            
            for scope_name in scope_names:
                if scope_name not in scope_ids:
                    logger.warning(f"  ⚠️ Scope '{scope_name}' not found, skipping assignment")
                    continue
                
                scope_id = scope_ids[scope_name]
                
                try:
                    # Check if assignment already exists
                    result = await self.session.execute(
                        text("""
                            SELECT EXISTS (
                                SELECT 1 FROM role_scopes 
                                WHERE role_id = :role_id AND scope_id = :scope_id
                            )
                        """),
                        {'role_id': role_id, 'scope_id': scope_id}
                    )
                    exists = result.scalar()
                    
                    if exists:
                        logger.info(f"  ✓ Role '{role_name}' already has scope '{scope_name}'")
                    else:
                        if not self.dry_run:
                            await self.session.execute(
                                text("""
                                    INSERT INTO role_scopes (role_id, scope_id)
                                    VALUES (:role_id, :scope_id)
                                """),
                                {'role_id': role_id, 'scope_id': scope_id}
                            )
                            logger.info(f"  ✅ Assigned scope '{scope_name}' to role '{role_name}'")
                        else:
                            logger.info(f"  🔍 [DRY RUN] Would assign scope '{scope_name}' to role '{role_name}'")
                            
                except Exception as e:
                    logger.error(f"  ❌ Error assigning scope '{scope_name}' to role '{role_name}': {e}")
                    raise
    
    async def create_admin_user(self, password: str, role_ids: Dict[str, str]) -> Optional[str]:
        """Create bootstrap admin user."""
        logger.info("Creating bootstrap admin user...")
        
        # Validate password
        validation_errors = validate_password(password, "admin")
        if validation_errors:
            logger.error(f"❌ Password validation failed: {', '.join(validation_errors)}")
            return None
        
        try:
            # Check if admin user already exists
            result = await self.session.execute(
                select(User).where(User.username == "admin")
            )
            existing_user = result.scalar_one_or_none()
            
            if existing_user:
                logger.info("  ✓ Admin user already exists")
                return str(existing_user.id)
            
            if not self.dry_run:
                # Hash password
                password_hash = hash_password(password)
                
                # Create admin user
                admin_user = User(
                    username="admin",
                    email="admin@permiso.com",
                    password_hash=password_hash,
                    first_name="System",
                    last_name="Administrator",
                    display_name="System Admin",
                    is_active=True,
                    is_verified=True,
                    is_superuser=True
                )
                
                self.session.add(admin_user)
                await self.session.flush()  # Get the ID
                
                # Assign admin role
                if 'admin' in role_ids:
                    await self.session.execute(
                        text("""
                            INSERT INTO user_roles (user_id, role_id)
                            VALUES (:user_id, :role_id)
                        """),
                        {'user_id': str(admin_user.id), 'role_id': role_ids['admin']}
                    )
                    logger.info("  ✅ Assigned admin role to bootstrap user")
                
                logger.info("  ✅ Created bootstrap admin user successfully")
                return str(admin_user.id)
            else:
                logger.info("  🔍 [DRY RUN] Would create bootstrap admin user")
                return str(uuid.uuid4())
                
        except Exception as e:
            logger.error(f"  ❌ Error creating admin user: {e}")
            raise
    
    async def use_sql_function(self, admin_password: Optional[str] = None) -> str:
        """Use the SQL function to initialize data."""
        logger.info("Using SQL function to initialize data...")
        
        try:
            password_hash = None
            if admin_password:
                # Validate password first
                validation_errors = validate_password(admin_password, "admin")
                if validation_errors:
                    logger.error(f"❌ Password validation failed: {', '.join(validation_errors)}")
                    return "ERROR: Password validation failed"
                
                password_hash = hash_password(admin_password)
                logger.info("  ✅ Password validated and hashed")
            
            if not self.dry_run:
                # Call the SQL function
                if password_hash:
                    result = await self.session.execute(
                        text("SELECT initialize_default_data(:password_hash)"),
                        {'password_hash': password_hash}
                    )
                else:
                    result = await self.session.execute(
                        text("SELECT initialize_default_data()")
                    )
                
                message = result.scalar()
                logger.info(f"  ✅ SQL function result: {message}")
                return message
            else:
                logger.info("  🔍 [DRY RUN] Would call initialize_default_data SQL function")
                return "DRY RUN: Would call SQL function"
                
        except Exception as e:
            logger.error(f"  ❌ Error calling SQL function: {e}")
            raise
    
    async def initialize_all(self, admin_password: Optional[str] = None, use_sql_function: bool = False) -> bool:
        """Initialize all default data."""
        logger.info("🚀 Starting database initialization...")
        
        try:
            # Check database connection
            if not await self.check_database_connection():
                return False
            
            # Check if tables exist
            if not await self.check_tables_exist():
                logger.error("❌ Required tables do not exist. Please run migrations first.")
                return False
            
            if use_sql_function:
                # Use SQL function approach
                result = await self.use_sql_function(admin_password)
                if not self.dry_run:
                    await self.session.commit()
                logger.info(f"✅ Initialization completed using SQL function: {result}")
                return True
            else:
                # Use Python approach
                role_ids = await self.create_roles()
                scope_ids = await self.create_scopes()
                await self.assign_scopes_to_roles(role_ids, scope_ids)
                
                if admin_password:
                    admin_id = await self.create_admin_user(admin_password, role_ids)
                    if not admin_id:
                        return False
                
                if not self.dry_run:
                    await self.session.commit()
                
                logger.info("✅ Database initialization completed successfully!")
                return True
                
        except Exception as e:
            logger.error(f"❌ Initialization failed: {e}")
            if self.session and not self.dry_run:
                await self.session.rollback()
            return False


async def main():
    """Main function to run the initialization script."""
    parser = argparse.ArgumentParser(
        description="Initialize Permiso database with default data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/initialize_default_data.py --admin-password "SecurePassword123"
  python scripts/initialize_default_data.py --use-sql-function --admin-password "SecurePassword123"
  python scripts/initialize_default_data.py --dry-run
  python scripts/initialize_default_data.py --environment production --admin-password "$(cat /secrets/admin_password)"
        """
    )
    
    parser.add_argument(
        '--admin-password',
        type=str,
        help='Password for the bootstrap admin user'
    )
    
    parser.add_argument(
        '--use-sql-function',
        action='store_true',
        help='Use the SQL function instead of Python implementation'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    
    parser.add_argument(
        '--environment',
        type=str,
        choices=['development', 'production', 'testing'],
        help='Override environment setting'
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
    
    # Override environment if specified
    if args.environment:
        os.environ['ENVIRONMENT'] = args.environment
        logger.info(f"Environment set to: {args.environment}")
    
    # Show configuration
    logger.info(f"Configuration:")
    logger.info(f"  Environment: {settings.ENVIRONMENT}")
    logger.info(f"  Database URL: {settings.DATABASE_URL}")
    logger.info(f"  Dry Run: {args.dry_run}")
    logger.info(f"  Use SQL Function: {args.use_sql_function}")
    logger.info(f"  Admin Password: {'Provided' if args.admin_password else 'Not provided'}")
    
    # Validate admin password if provided
    if args.admin_password:
        validation_errors = validate_password(args.admin_password, "admin")
        if validation_errors:
            logger.error(f"❌ Admin password validation failed:")
            for error in validation_errors:
                logger.error(f"  - {error}")
            return 1
        logger.info("✅ Admin password validation passed")
    
    # Run initialization
    try:
        async with DatabaseInitializer(dry_run=args.dry_run) as initializer:
            success = await initializer.initialize_all(
                admin_password=args.admin_password,
                use_sql_function=args.use_sql_function
            )
            
            if success:
                logger.info("🎉 Database initialization completed successfully!")
                return 0
            else:
                logger.error("💥 Database initialization failed!")
                return 1
                
    except KeyboardInterrupt:
        logger.info("⏹️ Initialization cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"💥 Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))