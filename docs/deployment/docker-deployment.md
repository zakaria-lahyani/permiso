# Docker Deployment Guide

This guide provides instructions for deploying the Keystone Authentication System using Docker and Docker Compose.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 2GB RAM
- 10GB available disk space

## Quick Start

### 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/your-org/keystone-auth.git
cd keystone-auth

# Copy environment template
cp .env.example .env

# Edit environment variables
nano .env
```

### 2. Basic Deployment

```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f app
```

### 3. Initialize Database

```bash
# Run database migrations
docker-compose exec app alembic upgrade head

# Create initial admin user (optional)
docker-compose exec app python -c "
from app.scripts.create_admin import create_admin_user
create_admin_user('admin', 'admin@example.com', 'SecurePassword123!')
"
```

## Docker Compose Configurations

### Development Configuration

`docker-compose.yml` (for development):

```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
      target: development
    ports:
      - "8000:8000"
    environment:
      - DEBUG=true
      - ENVIRONMENT=development
      - DATABASE_URL=postgresql+asyncpg://keystone:password@db:5432/keystone_dev
      - REDIS_URL=redis://redis:6379/0
    volumes:
      - .:/app
      - /app/__pycache__
    depends_on:
      - db
      - redis
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    networks:
      - keystone-network

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=keystone_dev
      - POSTGRES_USER=keystone
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_dev_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    networks:
      - keystone-network

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_dev_data:/data
    networks:
      - keystone-network

  # Optional: Database admin interface
  pgadmin:
    image: dpage/pgadmin4
    environment:
      - PGADMIN_DEFAULT_EMAIL=admin@example.com
      - PGADMIN_DEFAULT_PASSWORD=admin
    ports:
      - "5050:80"
    depends_on:
      - db
    networks:
      - keystone-network

volumes:
  postgres_dev_data:
  redis_dev_data:

networks:
  keystone-network:
    driver: bridge
```

### Production Configuration

`docker-compose.prod.yml` (for production):

```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
      target: production
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - DEBUG=false
    env_file:
      - .env.prod
    depends_on:
      - db
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - keystone-network

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=${POSTGRES_DB}
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_prod_data:/var/lib/postgresql/data
      - ./backups:/backups
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - keystone-network

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes
    volumes:
      - redis_prod_data:/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - keystone-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./logs/nginx:/var/log/nginx
    depends_on:
      - app
    restart: unless-stopped
    networks:
      - keystone-network

volumes:
  postgres_prod_data:
  redis_prod_data:

networks:
  keystone-network:
    driver: bridge
```

## Dockerfile

Multi-stage Dockerfile for optimal builds:

```dockerfile
# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Development stage
FROM python:3.11-slim as development

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder
COPY --from=builder /root/.local /root/.local

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app
USER app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Production stage
FROM python:3.11-slim as production

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder
COPY --from=builder /root/.local /root/.local

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app && \
    mkdir -p /var/log/keystone && \
    chown app:app /var/log/keystone

USER app

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

## Environment Configuration

### Development Environment

`.env` file for development:

```bash
# Application
APP_NAME=Keystone Authentication API
VERSION=1.0.0
DEBUG=true
ENVIRONMENT=development

# Server
HOST=0.0.0.0
PORT=8000

# Database
DATABASE_URL=postgresql+asyncpg://keystone:password@db:5432/keystone_dev
DATABASE_POOL_SIZE=5
DATABASE_MAX_OVERFLOW=0
DATABASE_ECHO=true

# Redis
REDIS_URL=redis://redis:6379/0
REDIS_PASSWORD=
REDIS_DECODE_RESPONSES=true

# JWT Configuration
JWT_SECRET_KEY=dev-secret-key-change-in-production
JWT_ALGORITHM=HS256
JWT_ISSUER=keystone-auth-dev
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=7
SERVICE_TOKEN_EXPIRE_MINUTES=60

# Security (relaxed for development)
PASSWORD_MIN_LENGTH=8
PASSWORD_MAX_LENGTH=128
PASSWORD_REQUIRE_UPPERCASE=false
PASSWORD_REQUIRE_LOWERCASE=false
PASSWORD_REQUIRE_DIGITS=false
PASSWORD_REQUIRE_SPECIAL=false

# Rate Limiting (relaxed for development)
RATE_LIMIT_LOGIN=10/minute
RATE_LIMIT_REGISTER=5/hour
RATE_LIMIT_API=1000/minute

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
ALLOWED_HEADERS=*
ALLOW_CREDENTIALS=true
ALLOWED_HOSTS=localhost,127.0.0.1

# Logging
LOG_LEVEL=DEBUG
LOG_FORMAT=text

# API Configuration
DOCS_URL=/docs
REDOC_URL=/redoc
OPENAPI_URL=/openapi.json
```

### Production Environment

`.env.prod` file for production:

```bash
# Application
APP_NAME=Keystone Authentication API
VERSION=1.0.0
DEBUG=false
ENVIRONMENT=production

# Server
HOST=0.0.0.0
PORT=8000

# Database
POSTGRES_DB=keystone_prod
POSTGRES_USER=keystone
POSTGRES_PASSWORD=your-secure-db-password
DATABASE_URL=postgresql+asyncpg://keystone:your-secure-db-password@db:5432/keystone_prod
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10
DATABASE_ECHO=false

# Redis
REDIS_PASSWORD=your-secure-redis-password
REDIS_URL=redis://:your-secure-redis-password@redis:6379/0
REDIS_DECODE_RESPONSES=true

# JWT Configuration
JWT_SECRET_KEY=your-super-secure-jwt-secret-key
JWT_ALGORITHM=HS256
JWT_ISSUER=keystone-auth-prod
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30
SERVICE_TOKEN_EXPIRE_MINUTES=15

# Security
PASSWORD_MIN_LENGTH=12
PASSWORD_MAX_LENGTH=128
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGITS=true
PASSWORD_REQUIRE_SPECIAL=true

# Rate Limiting
RATE_LIMIT_LOGIN=5/minute
RATE_LIMIT_REGISTER=3/hour
RATE_LIMIT_API=100/minute

# CORS
ALLOWED_ORIGINS=https://yourdomain.com
ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
ALLOWED_HEADERS=*
ALLOW_CREDENTIALS=true
ALLOWED_HOSTS=yourdomain.com

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# API Configuration (disabled in production)
DOCS_URL=
REDOC_URL=
OPENAPI_URL=
```

## Docker Commands

### Basic Operations

```bash
# Build images
docker-compose build

# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f app

# Execute commands in container
docker-compose exec app bash

# Scale application
docker-compose up -d --scale app=3
```

### Database Operations

```bash
# Run migrations
docker-compose exec app alembic upgrade head

# Create migration
docker-compose exec app alembic revision --autogenerate -m "description"

# Database backup
docker-compose exec db pg_dump -U keystone keystone_dev > backup.sql

# Database restore
docker-compose exec -T db psql -U keystone keystone_dev < backup.sql

# Access database shell
docker-compose exec db psql -U keystone keystone_dev
```

### Redis Operations

```bash
# Access Redis CLI
docker-compose exec redis redis-cli

# Monitor Redis
docker-compose exec redis redis-cli monitor

# Check Redis info
docker-compose exec redis redis-cli info
```

## Monitoring and Debugging

### Health Checks

```bash
# Check application health
curl http://localhost:8000/health

# Check all services
docker-compose ps

# View service logs
docker-compose logs app
docker-compose logs db
docker-compose logs redis
```

### Performance Monitoring

Add monitoring services to `docker-compose.monitoring.yml`:

```yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
    networks:
      - keystone-network

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./monitoring/grafana/datasources:/etc/grafana/provisioning/datasources
    networks:
      - keystone-network

volumes:
  grafana_data:

networks:
  keystone-network:
    external: true
```

Start monitoring:

```bash
# Start monitoring stack
docker-compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d

# Access Grafana
open http://localhost:3000
```

## Backup and Recovery

### Automated Backup Script

Create `scripts/docker-backup.sh`:

```bash
#!/bin/bash

BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Database backup
echo "Creating database backup..."
docker-compose exec -T db pg_dump -U keystone keystone_prod > "$BACKUP_DIR/db_backup_$TIMESTAMP.sql"

# Redis backup
echo "Creating Redis backup..."
docker-compose exec redis redis-cli BGSAVE
docker cp $(docker-compose ps -q redis):/data/dump.rdb "$BACKUP_DIR/redis_backup_$TIMESTAMP.rdb"

# Application data backup (if any)
echo "Creating application backup..."
tar -czf "$BACKUP_DIR/app_backup_$TIMESTAMP.tar.gz" logs/

# Cleanup old backups (keep last 7 days)
find $BACKUP_DIR -name "*backup_*" -mtime +7 -delete

echo "Backup completed: $TIMESTAMP"
```

### Recovery Procedure

```bash
# Stop services
docker-compose down

# Restore database
docker-compose up -d db
sleep 10
docker-compose exec -T db psql -U keystone keystone_prod < backups/db_backup_TIMESTAMP.sql

# Restore Redis
docker cp backups/redis_backup_TIMESTAMP.rdb $(docker-compose ps -q redis):/data/dump.rdb
docker-compose restart redis

# Start all services
docker-compose up -d
```

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Find process using port
   lsof -i :8000
   
   # Kill process
   kill -9 <PID>
   
   # Or change port in docker-compose.yml
   ports:
     - "8001:8000"
   ```

2. **Database Connection Issues**
   ```bash
   # Check database logs
   docker-compose logs db
   
   # Test connection
   docker-compose exec app python -c "
   from app.config.database import test_connection
   test_connection()
   "
   ```

3. **Memory Issues**
   ```bash
   # Check container memory usage
   docker stats
   
   # Increase memory limits in docker-compose.yml
   services:
     app:
       deploy:
         resources:
           limits:
             memory: 1G
   ```

4. **Permission Issues**
   ```bash
   # Fix file permissions
   sudo chown -R $USER:$USER .
   
   # Or run as root
   docker-compose exec --user root app bash
   ```

### Debugging Commands

```bash
# Enter container shell
docker-compose exec app bash

# Check environment variables
docker-compose exec app env

# View container processes
docker-compose exec app ps aux

# Check disk usage
docker-compose exec app df -h

# View network configuration
docker network ls
docker network inspect keystone_keystone-network
```

## Security Considerations

### Container Security

1. **Use Non-Root User**
   ```dockerfile
   RUN useradd --create-home --shell /bin/bash app
   USER app
   ```

2. **Minimal Base Images**
   ```dockerfile
   FROM python:3.11-slim  # Instead of python:3.11
   ```

3. **Security Scanning**
   ```bash
   # Scan images for vulnerabilities
   docker scan keystone:latest
   ```

### Network Security

```yaml
# Isolate services
networks:
  keystone-network:
    driver: bridge
    internal: true  # No external access
  
  web-network:
    driver: bridge  # External access for web services
```

### Secrets Management

```yaml
# Use Docker secrets
secrets:
  db_password:
    file: ./secrets/db_password.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt

services:
  app:
    secrets:
      - db_password
      - jwt_secret
```

## Best Practices

1. **Use Multi-Stage Builds** - Reduce image size
2. **Health Checks** - Monitor container health
3. **Resource Limits** - Prevent resource exhaustion
4. **Logging** - Centralized log management
5. **Secrets** - Never store secrets in images
6. **Updates** - Regular security updates
7. **Monitoring** - Comprehensive monitoring setup

This Docker deployment guide provides a complete setup for both development and production environments with proper security, monitoring, and maintenance procedures.