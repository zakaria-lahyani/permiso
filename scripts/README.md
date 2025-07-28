# Scripts Directory

This directory contains production-ready deployment and initialization scripts for the Permiso authentication system.

## Production Scripts

### [`deploy.py`](deploy.py)
Core deployment management script for Docker Compose operations.

```bash
# Build production images
python scripts/deploy.py build production --no-cache

# Deploy production environment
python scripts/deploy.py up production

# Stop production environment
python scripts/deploy.py down production
```

### [`fresh_deployment.py`](fresh_deployment.py)
**Recommended for production deployments**. Automated script that handles complete fresh deployment with database initialization.

```bash
# Complete fresh deployment with admin user
python scripts/fresh_deployment.py --admin-password "YourSecurePassword123"
```

Features:
- Stops existing containers
- Builds fresh images
- Deploys all services
- Runs database migrations
- Initializes default data
- Creates admin user
- Verifies deployment health

### [`init_database.py`](init_database.py)
Simple database initialization script for existing deployments.

```bash
# Initialize database with admin user
docker exec permiso-app-1 python scripts/init_database.py --password "YourPassword"
```

### [`initialize_default_data.py`](initialize_default_data.py)
Comprehensive database initialization script with full error handling and logging.

```bash
# Direct initialization (advanced usage)
python scripts/initialize_default_data.py --admin-password "YourPassword"
```

## Database Initialization Files

### [`init-prod-db.sql`](init-prod-db.sql)
Enhanced PostgreSQL initialization script with the `initialize_default_data()` function that:
- Creates default roles and scopes
- Creates admin user with specified password
- Returns detailed status messages
- Handles duplicate data gracefully

### Other SQL Files
- [`init-dev-db.sql`](init-dev-db.sql): Development environment initialization
- [`init-test-db.sql`](init-test-db.sql): Test environment initialization
- [`init-db.sql`](init-db.sql): Generic database initialization

## Usage Recommendations

### For Production Deployment
1. **First-time deployment**: Use [`fresh_deployment.py`](fresh_deployment.py)
2. **Existing deployment**: Use [`init_database.py`](init_database.py)
3. **Manual control**: Use [`deploy.py`](deploy.py) + [`init_database.py`](init_database.py)

### For Development
Use the development-specific scripts and Docker Compose configurations.

## Security Notes

- Always use strong passwords for admin users
- Store passwords securely (environment variables, secrets management)
- The scripts use Argon2 password hashing for security
- JWT tokens are configured with appropriate expiration times

## Migration Management

The system uses a consolidated migration approach:
- Single migration: `alembic/versions/001_create_complete_schema.py`
- Clean migration history
- No legacy conflicts
- Reliable deployments

See [`docs/deployment/PRODUCTION_DEPLOYMENT_GUIDE.md`](../docs/deployment/PRODUCTION_DEPLOYMENT_GUIDE.md) for complete deployment instructions.