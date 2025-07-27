# 🚀 Deployment Guide

This guide covers deployment strategies for the Permiso Admin Console in different environments.

## 📋 Prerequisites

### System Requirements
- **Node.js**: Version 16.0.0 or higher
- **npm**: Version 8.0.0 or higher
- **Docker**: Version 20.10.0 or higher
- **Docker Compose**: Version 2.0.0 or higher

### Network Requirements
- Access to Permiso Auth API (port 8000)
- Access to PostgreSQL database (port 5432)
- Access to Redis cache (port 6379)
- Outbound HTTPS access for CDN resources

## 🏗️ Build Process

### Local Development Build

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

### Environment Configuration

Create environment-specific configuration files:

#### Development (.env.local)
```bash
VITE_APP_NAME=Permiso Admin Console (Dev)
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws
VITE_AUTH_CLIENT_ID=admin-console-dev
VITE_AUTH_REDIRECT_URI=http://localhost:3000/auth/callback
VITE_DEV_MODE=true
VITE_DEBUG_MODE=true
VITE_MOCK_API=false
```

#### Staging (.env.staging)
```bash
VITE_APP_NAME=Permiso Admin Console (Staging)
VITE_API_BASE_URL=https://staging-api.permiso.com
VITE_WS_URL=wss://staging-api.permiso.com/ws
VITE_AUTH_CLIENT_ID=admin-console-staging
VITE_AUTH_REDIRECT_URI=https://staging-admin.permiso.com/auth/callback
VITE_DEV_MODE=false
VITE_DEBUG_MODE=false
VITE_MOCK_API=false
```

#### Production (.env.production)
```bash
VITE_APP_NAME=Permiso Admin Console
VITE_API_BASE_URL=https://api.permiso.com
VITE_WS_URL=wss://api.permiso.com/ws
VITE_AUTH_CLIENT_ID=admin-console
VITE_AUTH_REDIRECT_URI=https://admin.permiso.com/auth/callback
VITE_DEV_MODE=false
VITE_DEBUG_MODE=false
VITE_MOCK_API=false
VITE_SENTRY_DSN=https://your-sentry-dsn@sentry.io/project-id
VITE_GOOGLE_ANALYTICS_ID=GA-XXXXXXXXX
```

## 🐳 Docker Deployment

### Single Container Deployment

#### Build Docker Image
```bash
# Build production image
docker build -t permiso-admin-console:latest .

# Build with specific tag
docker build -t permiso-admin-console:v1.0.0 .

# Build development image
docker build -f docker/Dockerfile.dev -t permiso-admin-console:dev .
```

#### Run Container
```bash
# Run production container
docker run -d \
  --name permiso-admin-console \
  -p 80:80 \
  -e VITE_API_BASE_URL=https://api.permiso.com \
  permiso-admin-console:latest

# Run with custom configuration
docker run -d \
  --name permiso-admin-console \
  -p 3000:80 \
  --env-file .env.production \
  permiso-admin-console:latest
```

### Docker Compose Deployment

#### Development Environment
```bash
# Start development environment
docker-compose -f docker/docker-compose.dev.yml up -d

# View logs
docker-compose -f docker/docker-compose.dev.yml logs -f

# Stop environment
docker-compose -f docker/docker-compose.dev.yml down
```

#### Production Environment
```bash
# Start production environment
docker-compose -f docker/docker-compose.prod.yml up -d

# Scale admin console
docker-compose -f docker/docker-compose.prod.yml up -d --scale admin-console=3

# Update service
docker-compose -f docker/docker-compose.prod.yml pull admin-console
docker-compose -f docker/docker-compose.prod.yml up -d admin-console
```

### Production Docker Compose Configuration

```yaml
version: '3.8'

services:
  admin-console:
    image: permiso-admin-console:latest
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    environment:
      - VITE_API_BASE_URL=https://api.permiso.com
      - VITE_WS_URL=wss://api.permiso.com/ws
    volumes:
      - ./ssl:/etc/nginx/ssl:ro
      - ./logs:/var/log/nginx
    networks:
      - permiso-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M

  nginx-proxy:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - admin-console
    networks:
      - permiso-network

networks:
  permiso-network:
    external: true
```

## ☁️ Cloud Deployment

### AWS Deployment

#### Using AWS ECS

1. **Create ECR Repository**
```bash
# Create repository
aws ecr create-repository --repository-name permiso-admin-console

# Get login token
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com

# Tag and push image
docker tag permiso-admin-console:latest 123456789012.dkr.ecr.us-east-1.amazonaws.com/permiso-admin-console:latest
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/permiso-admin-console:latest
```

2. **ECS Task Definition**
```json
{
  "family": "permiso-admin-console",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::123456789012:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "admin-console",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/permiso-admin-console:latest",
      "portMappings": [
        {
          "containerPort": 80,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "VITE_API_BASE_URL",
          "value": "https://api.permiso.com"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/permiso-admin-console",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

#### Using AWS App Runner

```yaml
# apprunner.yaml
version: 1.0
runtime: docker
build:
  commands:
    build:
      - echo "Build started on `date`"
      - docker build -t permiso-admin-console .
run:
  runtime-version: latest
  command: nginx -g 'daemon off;'
  network:
    port: 80
    env: PORT
  env:
    - name: VITE_API_BASE_URL
      value: https://api.permiso.com
```

### Google Cloud Platform

#### Using Cloud Run

```bash
# Build and push to Container Registry
gcloud builds submit --tag gcr.io/PROJECT-ID/permiso-admin-console

# Deploy to Cloud Run
gcloud run deploy permiso-admin-console \
  --image gcr.io/PROJECT-ID/permiso-admin-console \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars VITE_API_BASE_URL=https://api.permiso.com
```

#### Using GKE

```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: permiso-admin-console
spec:
  replicas: 3
  selector:
    matchLabels:
      app: permiso-admin-console
  template:
    metadata:
      labels:
        app: permiso-admin-console
    spec:
      containers:
      - name: admin-console
        image: gcr.io/PROJECT-ID/permiso-admin-console:latest
        ports:
        - containerPort: 80
        env:
        - name: VITE_API_BASE_URL
          value: "https://api.permiso.com"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: permiso-admin-console-service
spec:
  selector:
    app: permiso-admin-console
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
  type: LoadBalancer
```

### Azure Deployment

#### Using Azure Container Instances

```bash
# Create resource group
az group create --name permiso-rg --location eastus

# Create container instance
az container create \
  --resource-group permiso-rg \
  --name permiso-admin-console \
  --image permiso-admin-console:latest \
  --dns-name-label permiso-admin \
  --ports 80 \
  --environment-variables VITE_API_BASE_URL=https://api.permiso.com
```

## 🔧 Nginx Configuration

### Production Nginx Configuration

```nginx
# nginx.conf
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    access_log /var/log/nginx/access.log main;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 16M;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss: https:;";

    server {
        listen 80;
        server_name _;
        root /usr/share/nginx/html;
        index index.html;

        # Health check endpoint
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }

        # Static assets with long cache
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            try_files $uri =404;
        }

        # API proxy
        location /api/ {
            proxy_pass http://permiso-auth:8000/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout 30s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
        }

        # WebSocket proxy
        location /ws {
            proxy_pass http://permiso-auth:8000/ws;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # SPA routing
        location / {
            try_files $uri $uri/ /index.html;
            add_header Cache-Control "no-cache, no-store, must-revalidate";
            add_header Pragma "no-cache";
            add_header Expires "0";
        }

        # Error pages
        error_page 404 /index.html;
        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root /usr/share/nginx/html;
        }
    }
}
```

## 🔒 SSL/TLS Configuration

### Let's Encrypt with Certbot

```bash
# Install certbot
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d admin.permiso.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### SSL Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name admin.permiso.com;

    ssl_certificate /etc/letsencrypt/live/admin.permiso.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/admin.permiso.com/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Rest of configuration...
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name admin.permiso.com;
    return 301 https://$server_name$request_uri;
}
```

## 📊 Monitoring & Health Checks

### Health Check Endpoint

The application includes a built-in health check endpoint at `/health` that returns:

```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "services": {
    "api": "connected",
    "websocket": "connected"
  }
}
```

### Docker Health Check

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost/health || exit 1
```

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 80
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health
    port: 80
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
```

## 🔄 CI/CD Pipeline

### GitHub Actions Workflow

```yaml
# .github/workflows/deploy.yml
name: Deploy Admin Console

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      
      - run: npm ci
      - run: npm run lint
      - run: npm run type-check
      - run: npm run test
      - run: npm run build

  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v1
      
      - name: Build and push Docker image
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          ECR_REPOSITORY: permiso-admin-console
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
          docker tag $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG $ECR_REGISTRY/$ECR_REPOSITORY:latest
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:latest
      
      - name: Deploy to ECS
        run: |
          aws ecs update-service --cluster permiso-cluster --service permiso-admin-console --force-new-deployment
```

## 🚨 Troubleshooting

### Common Issues

#### Build Failures
```bash
# Clear npm cache
npm cache clean --force

# Delete node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Check Node.js version
node --version
npm --version
```

#### Docker Issues
```bash
# Check container logs
docker logs permiso-admin-console

# Inspect container
docker inspect permiso-admin-console

# Execute shell in container
docker exec -it permiso-admin-console sh
```

#### Network Connectivity
```bash
# Test API connectivity
curl -f http://localhost:8000/health

# Test from container
docker exec permiso-admin-console curl -f http://permiso-auth:8000/health
```

### Performance Optimization

#### Bundle Analysis
```bash
# Analyze bundle size
npm run build
npx vite-bundle-analyzer dist
```

#### Nginx Optimization
```nginx
# Enable HTTP/2
listen 443 ssl http2;

# Optimize worker processes
worker_processes auto;
worker_connections 1024;

# Enable gzip compression
gzip on;
gzip_comp_level 6;
```

This deployment guide provides comprehensive instructions for deploying the Permiso Admin Console across different environments and platforms.