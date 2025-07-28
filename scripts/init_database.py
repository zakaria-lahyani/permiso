#!/usr/bin/env python3
"""
Simple wrapper script for database initialization.

This is a simplified interface to the comprehensive initialize_default_data.py script.
Perfect for quick setup and common use cases.

Usage:
    python scripts/init_database.py
    python scripts/init_database.py --password "MySecurePassword123"
    python scripts/init_database.py --dry-run
"""

import asyncio
import argparse
import sys
import os
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.initialize_default_data import DatabaseInitializer
from app.core.password import generate_secure_password


async def main():
    """Simple main function for database initialization."""
    parser = argparse.ArgumentParser(
        description="Initialize Permiso database with default data (simplified interface)"
    )
    
    parser.add_argument(
        '--password', '-p',
        type=str,
        help='Admin password (will generate secure password if not provided)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    
    parser.add_argument(
        '--use-sql-function',
        action='store_true',
        help='Use SQL function instead of Python implementation'
    )
    
    args = parser.parse_args()
    
    # Generate secure password if not provided
    admin_password = args.password
    if not admin_password and not args.dry_run:
        admin_password = generate_secure_password(16)
        print(f"🔐 Generated secure admin password: {admin_password}")
        print("⚠️  Please save this password securely!")
        print()
    
    print("🚀 Initializing Permiso database...")
    print(f"   Environment: {os.environ.get('ENVIRONMENT', 'production')}")
    print(f"   Dry run: {args.dry_run}")
    print(f"   Use SQL function: {args.use_sql_function}")
    print()
    
    try:
        async with DatabaseInitializer(dry_run=args.dry_run) as initializer:
            success = await initializer.initialize_all(
                admin_password=admin_password,
                use_sql_function=args.use_sql_function
            )
            
            if success:
                print("✅ Database initialization completed successfully!")
                if admin_password and not args.dry_run:
                    print()
                    print("📋 Admin user credentials:")
                    print(f"   Username: admin")
                    print(f"   Password: {admin_password}")
                    print(f"   Email: admin@permiso.com")
                return 0
            else:
                print("❌ Database initialization failed!")
                return 1
                
    except Exception as e:
        print(f"💥 Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))