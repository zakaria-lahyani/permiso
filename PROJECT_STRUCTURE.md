# Keystone Project Structure & Technical Specifications

## 📁 Project Directory Structure

```
keystone/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── keystone/
│   │   │           ├── KeystoneApplication.java
│   │   │           ├── config/
│   │   │           │   ├── SecurityConfig.java
│   │   │           │   ├── JwtConfig.java
│   │   │           │   ├── RedisConfig.java
│   │   │           │   └── DatabaseConfig.java
│   │   │           ├── controller/
│   │   │           │   ├── AuthController.java
│   │   │           │   ├── UserController.java
│   │   │           │   └── AdminController.java
│   │   │           ├── service/
│   │   │           │   ├── AuthService.java
│   │   │           │   ├── TokenService.java
│   │   │           │   ├── UserService.java
│   │   │           │   ├── RoleService.java
│   │   │           │   └── ClientService.java
│   │   │           ├── repository/
│   │   │           │   ├── UserRepository.java
│   │   │           │   ├── RoleRepository.java
│   │   │           │   ├── ScopeRepository.java
│   │   │           │   ├── ServiceClientRepository.java
│   │   │           │   └── RefreshTokenRepository.java
│   │   │           ├── entity/
│   │   │           │   ├── User.java
│   │   │           │   ├── Role.java
│   │   │           │   ├── Scope.java
│   │   │           │   ├── ServiceClient.java
│   │   │           │   └── RefreshToken.java
│   │   │           ├── dto/
│   │   │           │   ├── request/
│   │   │           │   │   ├── LoginRequest.java
│   │   │           │   │   ├── RegisterRequest.java
│   │   │           │   │   ├── RefreshTokenRequest.java
│   │   │           │   │   └── ClientCredentialsRequest.java
│   │   │           │   └── response/
│   │   │           │       ├── TokenResponse.java
│   │   │           │       ├── UserResponse.java
│   │   │           │       └── ErrorResponse.java
│   │   │           ├── security/
│   │   │           │   ├── JwtAuthenticationFilter.java
│   │   │           │   ├── JwtTokenProvider.java
│   │   │           │   ├── CustomUserDetailsService.java
│   │   │           │   └── PasswordPolicyValidator.java
│   │   │           ├── exception/
│   │   │           │   ├── GlobalExceptionHandler.java
│   │   │           │   ├── AuthenticationException.java
│   │   │           │   └── AuthorizationException.java
│   │   │           └── util/
│   │   │               ├── SecurityUtils.java
│   │   │               └── ValidationUtils.java
│   │   └── resources/
│   │       ├── application.yml
│   │       ├── application-dev.yml
│   │       ├── application-prod.yml
│   │       ├── data.sql
│   │       └── static/
│   └── test/
│       ├── java/
│       │   └── com/
│       │       └── keystone/
│       │           ├── integration/
│       │           │   ├── AuthControllerIntegrationTest.java
│       │           │   └── TokenServiceIntegrationTest.java
│       │           ├── unit/
│       │           │   ├── service/
│       │           │   │   ├── AuthServiceTest.java
│       │           │   │   └── TokenServiceTest.java
│       │           │   └── security/
│       │           │       └── JwtTokenProviderTest.java
│       │           └── testcontainers/
│       │               └── PostgreSQLTestContainer.java
│       └── resources/
│           ├── application-test.yml
│           └── test-data.sql
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── docker-compose.dev.yml
│   └── init-scripts/
│       └── init-db.sql
├── docs/
│   ├── API.md
│   ├── DEPLOYMENT.md
│   └── SECURITY.md
├── scripts/
│   ├── build.sh
│   ├── test.sh
│   └── deploy.sh
├── pom.xml
├── README.md
└── .gitignore
```

## 🔧 Maven Dependencies (pom.xml)

### Core Spring Boot Dependencies
```xml
<dependencies>
    <!-- Spring Boot Starters -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-redis</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-actuator</artifactId>
    </dependency>
</dependencies>
```

### Database & Caching
```xml
<!-- PostgreSQL Driver -->
<dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
</dependency>

<!-- Redis -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>

<!-- Connection Pooling -->
<dependency>
    <groupId>com.zaxxer</groupId>
    <artifactId>HikariCP</artifactId>
</dependency>
```

### Security & JWT
```xml
<!-- JWT -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.3</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.12.3</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.12.3</version>
</dependency>

<!-- Password Hashing -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-crypto</artifactId>
</dependency>
```

### Documentation & Testing
```xml
<!-- OpenAPI Documentation -->
<dependency>
    <groupId>org.springdoc</groupId>
    <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
    <version>2.2.0</version>
</dependency>

<!-- Testing -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>postgresql</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>junit-jupiter</artifactId>
    <scope>test</scope>
</dependency>
```

## ⚙️ Configuration Files

### application.yml Structure
```yaml
spring:
  profiles:
    active: dev
  application:
    name: keystone-auth
  
server:
  port: 8080
  servlet:
    context-path: /api/v1

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
  endpoint:
    health:
      show-details: when-authorized

logging:
  level:
    com.keystone: INFO
    org.springframework.security: DEBUG
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} - %msg%n"
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
```

### Security Configuration Properties
```yaml
keystone:
  jwt:
    secret: ${JWT_SECRET:your-256-bit-secret}
    access-token-expiration: 900000    # 15 minutes
    refresh-token-expiration: 2592000000 # 30 days
    service-token-expiration: 900000   # 15 minutes
    issuer: keystone-auth
  
  security:
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: true
      prevent-reuse-count: 5
    
    rate-limiting:
      login-attempts: 5
      lockout-duration: 300000 # 5 minutes
      
  redis:
    token-prefix: "keystone:token:"
    session-prefix: "keystone:session:"
    rate-limit-prefix: "keystone:rate:"
```

## 🐳 Docker Configuration

### Dockerfile
```dockerfile
FROM openjdk:21-jdk-slim

WORKDIR /app

COPY target/keystone-*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
```

### docker-compose.yml
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
      - REDIS_HOST=redis
    depends_on:
      - postgres
      - redis
    networks:
      - keystone-network

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: keystone
      POSTGRES_USER: keystone
      POSTGRES_PASSWORD: keystone123
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./docker/init-scripts:/docker-entrypoint-initdb.d
    networks:
      - keystone-network

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - keystone-network

volumes:
  postgres_data:
  redis_data:

networks:
  keystone-network:
    driver: bridge
```

## 🔐 Security Implementation Details

### JWT Token Structure
```java
public class JwtClaims {
    public static final String ISSUER = "iss";
    public static final String AUDIENCE = "aud";
    public static final String SUBJECT = "sub";
    public static final String EXPIRATION = "exp";
    public static final String ISSUED_AT = "iat";
    public static final String NOT_BEFORE = "nbf";
    public static final String JWT_ID = "jti";
    public static final String TOKEN_TYPE = "type";
    public static final String ROLES = "roles";
    public static final String SCOPES = "scopes";
    public static final String CLIENT_ID = "client_id";
}
```

### Password Policy Implementation
```java
@Component
public class PasswordPolicyValidator {
    
    public ValidationResult validate(String password, String username) {
        List<String> errors = new ArrayList<>();
        
        if (password.length() < minLength) {
            errors.add("Password must be at least " + minLength + " characters");
        }
        
        if (!containsUppercase(password)) {
            errors.add("Password must contain uppercase letters");
        }
        
        // Additional validation rules...
        
        return new ValidationResult(errors.isEmpty(), errors);
    }
}
```

## 📊 Database Schema Implementation

### JPA Entity Relationships
```java
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    @Column(unique = true, nullable = false)
    private String username;
    
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();
    
    // Additional fields and methods...
}
```

## 🧪 Testing Strategy Implementation

### Integration Test Configuration
```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class AuthControllerIntegrationTest {
    
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("keystone_test")
            .withUsername("test")
            .withPassword("test");
    
    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }
}
```

This structure provides a solid foundation for implementing the Keystone authentication system with proper separation of concerns, comprehensive testing, and production-ready configuration.