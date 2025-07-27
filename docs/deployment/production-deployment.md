# Production Deployment Guide

This guide provides comprehensive instructions for deploying the permiso Authentication System in a production environment.

## Prerequisites

Before deploying to production, ensure you have:

- Docker and Docker Compose installed
- PostgreSQL database (version 13+)
- Redis instance (version 6+)
- SSL certificates for HTTPS
- Domain name configured
- Load balancer (recommended for high availability)

## Environment Setup

### 1. Environment Variables

Create a `.env` file with production settings:

```bash
# Application
APP_NAME=permiso Authentication API
VERSION=1.0.0
DEBUG=false
ENVIRONMENT=production

# Server
HOST=0.0.0.0
PORT=8000

# Database
DATABASE_URL=postgresql+asyncpg://permiso:secure_password@db:5432/permiso_prod
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10
DATABASE_ECHO=false

# Redis
REDIS_URL=redis://redis:6379/0
REDIS_PASSWORD=secure_redis_password
REDIS_DECODE_RESPONSES=true

# JWT Configuration
JWT_SECRET_KEY=your-super-secure-jwt-secret-key-here
JWT_ALGORITHM=HS256
JWT_ISSUER=permiso-auth-prod
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
PASSWORD_PREVENT_REUSE_COUNT=10
PASSWORD_MAX_AGE_DAYS=90

# Rate Limiting
RATE_LIMIT_LOGIN=5/minute
RATE_LIMIT_REGISTER=3/hour
RATE_LIMIT_API=1000/minute
RATE_LIMIT_REFRESH=10/minute
RATE_LIMIT_SERVICE_TOKEN=50/minute

# Account Lockout
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=30

# CORS
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
ALLOWED_HEADERS=*
ALLOW_CREDENTIALS=true
ALLOWED_HOSTS=yourdomain.com,app.yourdomain.com

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE=/var/log/permiso/app.log

# Monitoring
ENABLE_METRICS=true
METRICS_PATH=/metrics

# Cache Configuration
CACHE_TOKEN_PREFIX=permiso:token:
CACHE_SESSION_PREFIX=permiso:session:
CACHE_RATE_LIMIT_PREFIX=permiso:rate:
CACHE_USER_PREFIX=permiso:user:
CACHE_DEFAULT_TTL=3600

# API Configuration
API_V1_PREFIX=/api/v1
DOCS_URL=
REDOC_URL=
OPENAPI_URL=
```

### 2. Docker Compose Configuration

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://permiso:${DB_PASSWORD}@db:5432/permiso_prod
      - REDIS_URL=redis://redis:6379/0
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - ENVIRONMENT=production
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/var/log/permiso
    restart: unless-stopped
    networks:
      - permiso-network

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=permiso_prod
      - POSTGRES_USER=permiso
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    ports:
      - "5432:5432"
    restart: unless-stopped
    networks:
      - permiso-network

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    restart: unless-stopped
    networks:
      - permiso-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
      - ./logs:/var/log/nginx
    depends_on:
      - app
    restart: unless-stopped
    networks:
      - permiso-network

volumes:
  postgres_data:
  redis_data:

networks:
  permiso-network:
    driver: bridge
```

### 3. Nginx Configuration

Create `nginx/nginx.conf`:

```nginx
events {
    worker_connections 1024;
}

http {
    upstream permiso_app {
        server app:8000;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name yourdomain.com;
        return 301 https://$server_name$request_uri;
    }

    # HTTPS Server
    server {
        listen 443 ssl http2;
        server_name yourdomain.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;

        # Logging
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        # API endpoints
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://permiso_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Authentication endpoints with stricter rate limiting
        location /api/v1/auth/token {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://permiso_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check
        location /health {
            proxy_pass http://permiso_app;
            access_log off;
        }

        # Metrics (restrict access)
        location /metrics {
            allow 10.0.0.0/8;
            allow 172.16.0.0/12;
            allow 192.168.0.0/16;
            deny all;
            proxy_pass http://permiso_app;
        }
    }
}
```

## Database Setup

### 1. Database Migration

Run database migrations:

```bash
# Run migrations
docker-compose -f docker-compose.prod.yml exec app alembic upgrade head

# Create initial admin user (optional)
docker-compose -f docker-compose.prod.yml exec app python -m scripts.create_admin_user
```

### 2. Database Backup Strategy

Create a backup script `scripts/backup_db.sh`:

```bash
#!/bin/bash

BACKUP_DIR="/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="permiso_backup_${TIMESTAMP}.sql"

# Create backup
docker-compose -f docker-compose.prod.yml exec -T db pg_dump -U permiso permiso_prod > "${BACKUP_DIR}/${BACKUP_FILE}"

# Compress backup
gzip "${BACKUP_DIR}/${BACKUP_FILE}"

# Keep only last 30 days of backups
find ${BACKUP_DIR} -name "permiso_backup_*.sql.gz" -mtime +30 -delete

echo "Backup completed: ${BACKUP_FILE}.gz"
```

Set up daily backups with cron:

```bash
# Add to crontab
0 2 * * * /path/to/scripts/backup_db.sh
```

## Security Configuration

### 1. SSL/TLS Setup

Generate SSL certificates (using Let's Encrypt):

```bash
# Install certbot
sudo apt-get install certbot

# Generate certificates
sudo certbot certonly --standalone -d yourdomain.com

# Copy certificates to nginx directory
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem nginx/ssl/key.pem
```

### 2. Firewall Configuration

Configure UFW firewall:

```bash
# Enable firewall
sudo ufw enable

# Allow SSH
sudo ufw allow ssh

# Allow HTTP and HTTPS
sudo ufw allow 80
sudo ufw allow 443

# Allow database access only from app servers
sudo ufw allow from 172.16.0.0/12 to any port 5432

# Allow Redis access only from app servers
sudo ufw allow from 172.16.0.0/12 to any port 6379
```

### 3. Secret Management

Use Docker secrets or external secret management:

```yaml
# Add to docker-compose.prod.yml
secrets:
  jwt_secret:
    external: true
  db_password:
    external: true
  redis_password:
    external: true

services:
  app:
    secrets:
      - jwt_secret
      - db_password
      - redis_password
```

## Monitoring and Logging

### 1. Application Monitoring

Set up Prometheus monitoring:

```yaml
# Add to docker-compose.prod.yml
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
    networks:
      - permiso-network

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
    networks:
      - permiso-network
```

### 2. Log Management

Configure log rotation:

```bash
# Create logrotate configuration
sudo tee /etc/logrotate.d/permiso << EOF
/var/log/permiso/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        docker-compose -f /path/to/docker-compose.prod.yml restart app
    endscript
}
EOF
```

### 3. Health Checks

Implement health check monitoring:

```bash
#!/bin/bash
# scripts/health_check.sh

HEALTH_URL="https://yourdomain.com/health"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)

if [ $RESPONSE -eq 200 ]; then
    echo "Health check passed"
    exit 0
else
    echo "Health check failed with status: $RESPONSE"
    # Send alert notification
    exit 1
fi
```

## Deployment Process

### 1. Pre-deployment Checklist

- [ ] Environment variables configured
- [ ] SSL certificates installed
- [ ] Database backups completed
- [ ] Health checks passing
- [ ] Load balancer configured
- [ ] Monitoring systems ready

### 2. Deployment Steps

```bash
# 1. Pull latest code
git pull origin main

# 2. Build new images
docker-compose -f docker-compose.prod.yml build

# 3. Run database migrations
docker-compose -f docker-compose.prod.yml run --rm app alembic upgrade head

# 4. Deploy with zero downtime
docker-compose -f docker-compose.prod.yml up -d --no-deps app

# 5. Verify deployment
curl -f https://yourdomain.com/health

# 6. Run smoke tests
python scripts/smoke_tests.py
```

### 3. Rollback Procedure

```bash
# 1. Identify last known good version
docker images | grep permiso

# 2. Rollback to previous version
docker-compose -f docker-compose.prod.yml stop app
docker tag permiso:previous permiso:latest
docker-compose -f docker-compose.prod.yml up -d app

# 3. Rollback database if needed
docker-compose -f docker-compose.prod.yml exec -T db psql -U permiso permiso_prod < /backups/last_good_backup.sql
```

## Performance Optimization

### 1. Database Optimization

```sql
-- Create indexes for better performance
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_users_username ON users(username);
CREATE INDEX CONCURRENTLY idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX CONCURRENTLY idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX CONCURRENTLY idx_user_sessions_expires_at ON user_sessions(expires_at);

-- Analyze tables
ANALYZE users;
ANALYZE refresh_tokens;
ANALYZE user_sessions;
```

### 2. Redis Configuration

```bash
# Add to redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

### 3. Application Tuning

```bash
# Environment variables for performance
UVICORN_WORKERS=4
UVICORN_MAX_REQUESTS=1000
UVICORN_MAX_REQUESTS_JITTER=100
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10
```

## Maintenance

### 1. Regular Tasks

- Daily database backups
- Weekly log rotation
- Monthly security updates
- Quarterly performance reviews

### 2. Monitoring Alerts

Set up alerts for:
- High error rates
- Database connection issues
- Memory/CPU usage
- Failed authentication attempts
- SSL certificate expiration

### 3. Update Procedure

```bash
# 1. Schedule maintenance window
# 2. Create backup
./scripts/backup_db.sh

# 3. Update application
git pull origin main
docker-compose -f docker-compose.prod.yml build
docker-compose -f docker-compose.prod.yml up -d

# 4. Run migrations
docker-compose -f docker-compose.prod.yml exec app alembic upgrade head

# 5. Verify functionality
python scripts/smoke_tests.py
```

## Troubleshooting

### Common Issues

1. **Database Connection Issues**
   ```bash
   # Check database status
   docker-compose -f docker-compose.prod.yml logs db
   
   # Test connection
   docker-compose -f docker-compose.prod.yml exec app python -c "from app.config.database import test_connection; test_connection()"
   ```

2. **Redis Connection Issues**
   ```bash
   # Check Redis status
   docker-compose -f docker-compose.prod.yml logs redis
   
   # Test Redis connection
   docker-compose -f docker-compose.prod.yml exec redis redis-cli ping
   ```

3. **High Memory Usage**
   ```bash
   # Monitor memory usage
   docker stats
   
   # Check application metrics
   curl https://yourdomain.com/metrics
   ```

### Emergency Procedures

1. **Service Outage**
   - Check health endpoints
   - Review application logs
   - Verify database connectivity
   - Check external dependencies

2. **Security Incident**
   - Rotate JWT secrets
   - Invalidate all sessions
   - Review access logs
   - Update security configurations

3. **Data Recovery**
   - Stop application
   - Restore from backup
   - Run integrity checks
   - Restart services

## Support and Maintenance

For ongoing support:
- Monitor application logs daily
- Review security alerts weekly
- Update dependencies monthly
- Conduct security audits quarterly

This deployment guide ensures a secure, scalable, and maintainable production deployment of the permiso Authentication System.