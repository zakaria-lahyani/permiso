# Keystone Security & Deployment Guide

## 🔐 Security Implementation

### 1. Password Security

#### Password Policy Configuration
```yaml
keystone:
  security:
    password-policy:
      min-length: 8
      max-length: 128
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-reuse-count: 5
      max-age-days: 90
      complexity-score: 3
```

#### Password Hashing Strategy
```java
@Configuration
public class PasswordConfig {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
    
    @Bean
    public Argon2PasswordEncoder argon2PasswordEncoder() {
        return new Argon2PasswordEncoder(16, 32, 1, 4096, 3);
    }
}
```

### 2. JWT Security

#### Token Signing Configuration
```yaml
keystone:
  jwt:
    # For development - use HS256 with strong secret
    algorithm: HS256
    secret: ${JWT_SECRET:your-256-bit-secret-key-here}
    
    # For production - use RS256 with key pairs
    # algorithm: RS256
    # private-key-path: /etc/keystone/keys/private.pem
    # public-key-path: /etc/keystone/keys/public.pem
```

#### Token Validation Rules
```java
@Component
public class JwtValidator {
    
    public ValidationResult validateToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .requireIssuer("keystone-auth")
                .requireAudience("expected-audience")
                .build()
                .parseClaimsJws(token)
                .getBody();
                
            // Validate custom claims
            validateTokenType(claims);
            validateScopes(claims);
            validateJti(claims);
            
            return ValidationResult.valid();
        } catch (JwtException e) {
            return ValidationResult.invalid(e.getMessage());
        }
    }
}
```

### 3. Rate Limiting & Brute Force Protection

#### Redis-based Rate Limiting
```java
@Component
public class RateLimitService {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    public boolean isAllowed(String key, int limit, Duration window) {
        String redisKey = "rate_limit:" + key;
        String current = redisTemplate.opsForValue().get(redisKey);
        
        if (current == null) {
            redisTemplate.opsForValue().set(redisKey, "1", window);
            return true;
        }
        
        int count = Integer.parseInt(current);
        if (count >= limit) {
            return false;
        }
        
        redisTemplate.opsForValue().increment(redisKey);
        return true;
    }
}
```

#### Account Lockout Strategy
```java
@Service
public class AccountLockoutService {
    
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);
    
    public void recordFailedAttempt(String username) {
        String key = "failed_attempts:" + username;
        String attempts = redisTemplate.opsForValue().get(key);
        
        int count = attempts != null ? Integer.parseInt(attempts) : 0;
        count++;
        
        if (count >= MAX_ATTEMPTS) {
            lockAccount(username);
        }
        
        redisTemplate.opsForValue().set(key, String.valueOf(count), LOCKOUT_DURATION);
    }
    
    public boolean isAccountLocked(String username) {
        return redisTemplate.hasKey("locked_account:" + username);
    }
}
```

### 4. Input Validation & Sanitization

#### Request Validation
```java
@RestController
@Validated
public class AuthController {
    
    @PostMapping("/auth/token")
    public ResponseEntity<TokenResponse> authenticate(
            @Valid @RequestBody LoginRequest request) {
        
        // Input sanitization
        String sanitizedUsername = SecurityUtils.sanitizeInput(request.getUsername());
        
        // Additional validation
        if (!ValidationUtils.isValidEmail(sanitizedUsername)) {
            throw new ValidationException("Invalid email format");
        }
        
        return authService.authenticate(sanitizedUsername, request.getPassword());
    }
}
```

#### SQL Injection Prevention
```java
@Repository
public class UserRepository {
    
    @Query("SELECT u FROM User u WHERE u.username = :username AND u.enabled = true")
    Optional<User> findByUsernameAndEnabled(@Param("username") String username);
    
    // Always use parameterized queries
    @Query(value = "SELECT * FROM users WHERE email = ? AND status = ?", nativeQuery = true)
    List<User> findByEmailAndStatus(String email, String status);
}
```

## 🚀 Deployment Configuration

### 1. Environment-Specific Configurations

#### Development Environment
```yaml
# application-dev.yml
spring:
  datasource:
    url: jdbc:h2:mem:keystone
    driver-class-name: org.h2.Driver
    username: sa
    password: 
  
  jpa:
    hibernate:
      ddl-auto: create-drop
    show-sql: true
  
  redis:
    host: localhost
    port: 6379

keystone:
  jwt:
    secret: dev-secret-key-not-for-production
    access-token-expiration: 3600000  # 1 hour for dev
```

#### Production Environment
```yaml
# application-prod.yml
spring:
  datasource:
    url: jdbc:postgresql://${DB_HOST:localhost}:${DB_PORT:5432}/${DB_NAME:keystone}
    username: ${DB_USERNAME:keystone}
    password: ${DB_PASSWORD}
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      connection-timeout: 30000
      idle-timeout: 600000
      max-lifetime: 1800000
  
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
  
  redis:
    host: ${REDIS_HOST:localhost}
    port: ${REDIS_PORT:6379}
    password: ${REDIS_PASSWORD:}
    timeout: 2000ms
    lettuce:
      pool:
        max-active: 8
        max-idle: 8
        min-idle: 0

server:
  port: 8080
  ssl:
    enabled: true
    key-store: ${SSL_KEYSTORE_PATH:/etc/keystone/ssl/keystore.p12}
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
    key-store-type: PKCS12

keystone:
  jwt:
    secret: ${JWT_SECRET}
    access-token-expiration: 900000   # 15 minutes
    refresh-token-expiration: 2592000000  # 30 days
```

### 2. Docker Production Setup

#### Multi-stage Dockerfile
```dockerfile
# Build stage
FROM maven:3.9-openjdk-21-slim AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn clean package -DskipTests

# Runtime stage
FROM openjdk:21-jdk-slim
RUN addgroup --system keystone && adduser --system --group keystone
WORKDIR /app

# Install security updates
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Copy application
COPY --from=build /app/target/keystone-*.jar app.jar
RUN chown keystone:keystone app.jar

# Create directories for logs and config
RUN mkdir -p /app/logs /app/config && chown -R keystone:keystone /app

USER keystone

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/v1/actuator/health || exit 1

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
```

#### Production Docker Compose
```yaml
version: '3.8'

services:
  keystone-app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - DB_HOST=postgres
      - DB_USERNAME=keystone
      - DB_PASSWORD_FILE=/run/secrets/db_password
      - REDIS_HOST=redis
      - REDIS_PASSWORD_FILE=/run/secrets/redis_password
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
    secrets:
      - db_password
      - redis_password
      - jwt_secret
    volumes:
      - ./logs:/app/logs
      - ./config:/app/config
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped
    networks:
      - keystone-network

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: keystone
      POSTGRES_USER: keystone
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./docker/init-scripts:/docker-entrypoint-initdb.d:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keystone"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped
    networks:
      - keystone-network

  redis:
    image: redis:7-alpine
    command: >
      sh -c "redis-server --requirepass $$(cat /run/secrets/redis_password) --appendonly yes"
    secrets:
      - redis_password
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "--no-auth-warning", "-a", "$$(cat /run/secrets/redis_password)", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped
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
    depends_on:
      - keystone-app
    restart: unless-stopped
    networks:
      - keystone-network

secrets:
  db_password:
    file: ./secrets/db_password.txt
  redis_password:
    file: ./secrets/redis_password.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt

volumes:
  postgres_data:
  redis_data:

networks:
  keystone-network:
    driver: bridge
```

### 3. Nginx Reverse Proxy Configuration

```nginx
# nginx/nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream keystone {
        server keystone-app:8080;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;

    server {
        listen 80;
        server_name auth.yourdomain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name auth.yourdomain.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
        ssl_prefer_server_ciphers off;

        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        # Auth endpoints with stricter rate limiting
        location /api/v1/auth/ {
            limit_req zone=auth burst=10 nodelay;
            proxy_pass http://keystone;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Other API endpoints
        location /api/v1/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://keystone;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check endpoint (no rate limiting)
        location /api/v1/actuator/health {
            proxy_pass http://keystone;
            access_log off;
        }
    }
}
```

### 4. Monitoring & Logging

#### Logging Configuration
```yaml
# logback-spring.xml
<configuration>
    <springProfile name="prod">
        <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
            <file>/app/logs/keystone.log</file>
            <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
                <fileNamePattern>/app/logs/keystone.%d{yyyy-MM-dd}.%i.gz</fileNamePattern>
                <maxFileSize>100MB</maxFileSize>
                <maxHistory>30</maxHistory>
                <totalSizeCap>3GB</totalSizeCap>
            </rollingPolicy>
            <encoder class="net.logstash.logback.encoder.LoggingEventCompositeJsonEncoder">
                <providers>
                    <timestamp/>
                    <logLevel/>
                    <loggerName/>
                    <message/>
                    <mdc/>
                    <stackTrace/>
                </providers>
            </encoder>
        </appender>
        
        <logger name="com.keystone" level="INFO"/>
        <logger name="org.springframework.security" level="WARN"/>
        <root level="WARN">
            <appender-ref ref="FILE"/>
        </root>
    </springProfile>
</configuration>
```

#### Security Event Logging
```java
@Component
public class SecurityEventLogger {
    
    private static final Logger securityLogger = LoggerFactory.getLogger("SECURITY");
    
    public void logAuthenticationSuccess(String username, String clientId, String ipAddress) {
        securityLogger.info("Authentication successful - username: {}, client: {}, ip: {}", 
            username, clientId, ipAddress);
    }
    
    public void logAuthenticationFailure(String username, String reason, String ipAddress) {
        securityLogger.warn("Authentication failed - username: {}, reason: {}, ip: {}", 
            username, reason, ipAddress);
    }
    
    public void logTokenGenerated(String tokenType, String subject, String audience) {
        securityLogger.info("Token generated - type: {}, subject: {}, audience: {}", 
            tokenType, subject, audience);
    }
    
    public void logSuspiciousActivity(String activity, String details, String ipAddress) {
        securityLogger.error("Suspicious activity detected - activity: {}, details: {}, ip: {}", 
            activity, details, ipAddress);
    }
}
```

### 5. Backup & Recovery

#### Database Backup Script
```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backups"
DB_NAME="keystone"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup
docker exec keystone_postgres_1 pg_dump -U keystone $DB_NAME > "$BACKUP_DIR/keystone_$TIMESTAMP.sql"

# Compress backup
gzip "$BACKUP_DIR/keystone_$TIMESTAMP.sql"

# Remove backups older than 30 days
find $BACKUP_DIR -name "keystone_*.sql.gz" -mtime +30 -delete

echo "Backup completed: keystone_$TIMESTAMP.sql.gz"
```

#### Recovery Procedure
```bash
#!/bin/bash
# restore.sh

BACKUP_FILE=$1
DB_NAME="keystone"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

# Stop application
docker-compose stop keystone-app

# Restore database
gunzip -c "$BACKUP_FILE" | docker exec -i keystone_postgres_1 psql -U keystone -d $DB_NAME

# Start application
docker-compose start keystone-app

echo "Database restored from $BACKUP_FILE"
```

### 6. Security Checklist

#### Pre-deployment Security Checklist
- [ ] Change all default passwords and secrets
- [ ] Enable HTTPS/TLS with valid certificates
- [ ] Configure proper CORS policies
- [ ] Set up rate limiting and DDoS protection
- [ ] Enable security headers (HSTS, CSP, etc.)
- [ ] Configure proper logging and monitoring
- [ ] Set up automated backups
- [ ] Test disaster recovery procedures
- [ ] Perform security vulnerability scanning
- [ ] Configure firewall rules
- [ ] Set up intrusion detection
- [ ] Enable audit logging
- [ ] Test authentication and authorization flows
- [ ] Verify token expiration and revocation
- [ ] Test password policy enforcement

#### Runtime Security Monitoring
- [ ] Monitor failed authentication attempts
- [ ] Track unusual token usage patterns
- [ ] Alert on multiple failed login attempts
- [ ] Monitor for SQL injection attempts
- [ ] Track API rate limit violations
- [ ] Monitor system resource usage
- [ ] Set up automated security updates
- [ ] Regular security assessments
- [ ] Monitor third-party dependencies for vulnerabilities
- [ ] Regular penetration testing

This comprehensive security and deployment guide ensures that your Keystone authentication system is production-ready with enterprise-grade security measures.