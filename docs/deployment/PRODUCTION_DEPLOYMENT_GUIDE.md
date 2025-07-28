# Production Deployment Guide

This guide provides the complete process for deploying Permiso in production with automatic admin user creation.

## Prerequisites

- Docker and Docker Compose installed
- Environment variables configured in `.env.prod`
- SSL certificates (if using HTTPS)

## Quick Deployment

### Option 1: Automated Fresh Deployment (Recommended)

Use the automated fresh deployment script for a complete setup:

```bash
# Deploy with automatic admin user creation
python scripts/fresh_deployment.py --admin-password "YourSecurePassword123"
```

This script will:
- Stop any existing containers
- Build fresh images
- Deploy all services
- Run database migrations
- Initialize default data with admin user
- Verify deployment health

### Option 2: Manual Deployment

If you prefer manual control:

```bash
# 1. Build and deploy
python scripts/deploy.py build production --no-cache
python scripts/deploy.py up production

# 2. Initialize database (after containers are running)
docker exec permiso-app-1 python scripts/init_database.py --password "YourSecurePassword123"
```

## Environment Configuration

Ensure your `.env.prod` file contains:

```env
# Database
POSTGRES_DB=permiso
POSTGRES_USER=permiso
POSTGRES_PASSWORD=your_secure_db_password
DATABASE_URL=postgresql://permiso:your_secure_db_password@permiso-postgres-prod:5432/permiso

# JWT Configuration
JWT_SECRET_KEY=your_jwt_secret_key_here
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Redis
REDIS_URL=redis://permiso-redis-prod:6379/0

# Application
ENVIRONMENT=production
DEBUG=false
```

## Database Initialization

The system includes enhanced database initialization with automatic admin user creation:

### Default Admin User
- **Username**: `admin`
- **Email**: `admin@permiso.local`
- **Password**: As specified during initialization
- **Roles**: `super_admin` with all scopes

### Default Roles and Scopes
The system creates these default roles:
- `super_admin`: Full system access
- `admin`: Administrative access
- `user`: Basic user access

With comprehensive scopes for all API endpoints.

## Verification

After deployment, verify the system:

```bash
# Check container status
docker ps --filter name=permiso

# Check application health
curl http://localhost/health

# Test admin authentication
curl -X POST http://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "YourSecurePassword123"}'
```

## Service Architecture

The production deployment includes:

- **Application**: FastAPI app with Gunicorn (port 8000)
- **Database**: PostgreSQL 15 (port 5432)
- **Cache**: Redis 7 (port 6379)
- **Reverse Proxy**: Nginx (ports 80/443)

## Security Features

- Argon2 password hashing
- JWT token authentication with refresh tokens
- Role-based access control (RBAC)
- Comprehensive audit logging
- Session management
- HTTPS support (with SSL certificates)

## Troubleshooting

### Common Issues

1. **Migration Failures**: Use the fresh deployment script to rebuild with clean migrations
2. **Container Connection Issues**: Ensure all containers are healthy before initialization
3. **Authentication Issues**: Verify JWT configuration and password hashing

### Logs

Check container logs for debugging:

```bash
# Application logs
docker logs permiso-app-1

# Database logs
docker logs permiso-postgres-prod

# Nginx logs
docker logs permiso-nginx-prod
```

## Maintenance

### Backup Database
```bash
docker exec permiso-postgres-prod pg_dump -U permiso permiso > backup.sql
```

### Update Application
```bash
# Pull latest changes
git pull

# Rebuild and redeploy
python scripts/fresh_deployment.py --admin-password "YourPassword"
```

## Scripts Reference

- **`scripts/deploy.py`**: Core deployment management
- **`scripts/fresh_deployment.py`**: Automated fresh deployment
- **`scripts/init_database.py`**: Database initialization
- **`scripts/initialize_default_data.py`**: Comprehensive data initialization

## Migration Management

The system uses a consolidated migration approach:
- Single migration file: `001_create_complete_schema.py`
- Reflects current model state
- Clean migration history
- No legacy migration conflicts

This ensures reliable deployments and consistent database schema across environments.