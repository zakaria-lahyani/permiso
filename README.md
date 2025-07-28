# Permiso Authentication System

A production-ready centralized authentication and authorization system built with FastAPI, featuring automatic admin user creation and comprehensive role-based access control.

## Features

- **JWT-based authentication** with refresh token rotation
- **Role-based access control (RBAC)** with fine-grained scopes
- **Automatic admin user creation** during deployment
- **Session management** with Redis caching
- **PostgreSQL database** with clean migration history
- **Docker deployment** with production-ready configuration
- **Comprehensive security** with Argon2 password hashing
- **Health monitoring** and audit logging

## Quick Start

### Production Deployment (Recommended)

Deploy the complete system with automatic admin user creation:

```bash
# Automated fresh deployment
python scripts/fresh_deployment.py --admin-password "YourSecurePassword123"
```

This single command will:
- Build and deploy all services
- Run database migrations
- Create default roles and scopes
- Create admin user with specified password
- Verify deployment health

### Manual Deployment

For more control over the deployment process:

```bash
# Build and deploy
python scripts/deploy.py build production --no-cache
python scripts/deploy.py up production

# Initialize database (after containers are running)
docker exec permiso-app-1 python scripts/init_database.py --password "YourSecurePassword123"
```

### Development

```bash
# Development environment
python scripts/deploy.py up development
```

### Testing

```bash
# Run tests
python scripts/deploy.py test
```

## Default Admin User

After deployment, you can authenticate with:
- **Username**: `admin`
- **Email**: `admin@permiso.local`
- **Password**: As specified during initialization
- **Role**: `super_admin` (full system access)

## API Access

Test the authentication system:

```bash
# Health check
curl http://localhost/health

# Admin login
curl -X POST http://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "YourSecurePassword123"}'
```

## Architecture

- **Application**: FastAPI with Gunicorn
- **Database**: PostgreSQL 15 with Alembic migrations
- **Cache**: Redis 7 for session management
- **Reverse Proxy**: Nginx with SSL support
- **Containerization**: Docker Compose for orchestration

## Security Features

- **Argon2 password hashing** for secure password storage
- **JWT tokens** with configurable expiration
- **Refresh token rotation** for enhanced security
- **Role-based permissions** with granular scopes
- **Session management** with Redis
- **Audit logging** for security monitoring
- **HTTPS support** with SSL certificates

## Documentation

Comprehensive documentation is available in the [`/docs`](docs/) directory:

- **[Production Deployment Guide](docs/deployment/PRODUCTION_DEPLOYMENT_GUIDE.md)**: Complete deployment instructions
- **[Scripts Documentation](scripts/README.md)**: Available deployment and initialization scripts
- **[API Documentation](docs/api/)**: Detailed API reference
- **[Architecture Overview](docs/architecture/)**: System design and components
- **[Security Guide](docs/security/)**: Security best practices

## Scripts Reference

- **[`scripts/fresh_deployment.py`](scripts/fresh_deployment.py)**: Automated fresh deployment (recommended)
- **[`scripts/deploy.py`](scripts/deploy.py)**: Core deployment management
- **[`scripts/init_database.py`](scripts/init_database.py)**: Database initialization
- **[`scripts/initialize_default_data.py`](scripts/initialize_default_data.py)**: Comprehensive data initialization

## Environment Configuration

Configure your environment in `.env.prod`:

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

## Migration Management

The system uses a consolidated migration approach for reliability:
- **Single migration**: `alembic/versions/001_create_complete_schema.py`
- **Clean history**: No legacy migration conflicts
- **Current state**: Reflects exact model definitions
- **Reliable deployments**: Consistent across environments

## Support

For issues, questions, or contributions, please refer to the documentation or create an issue in the project repository.

## License

This project is licensed under the MIT License.