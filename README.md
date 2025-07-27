# Keystone Authentication System

A centralized authentication and authorization system built with FastAPI, providing secure user management, role-based access control, and JWT token authentication.

## Features

- **User Management**: Complete user lifecycle management with secure password handling
- **Role-Based Access Control**: Flexible role and permission system
- **JWT Authentication**: Secure token-based authentication with refresh tokens
- **Service Client Authentication**: Support for service-to-service authentication
- **Redis Caching**: High-performance caching and session management
- **PostgreSQL Database**: Robust data persistence with async support
- **Comprehensive Testing**: Full test suite with Docker containerization
- **API Documentation**: Auto-generated OpenAPI/Swagger documentation

## Quick Start

### Using Docker (Recommended)

1. **Run tests with Docker containers:**
   ```bash
   # Windows PowerShell
   .\run-tests-docker.ps1
   
   # Windows Command Prompt
   run_tests.bat
   
   # Direct Python execution
   python run_tests.py
   ```

2. **Start the development environment:**
   ```bash
   docker compose up -d keystone-dev
   ```

3. **Run the application:**
   ```bash
   docker compose up -d keystone-app
   ```

### Local Development

1. **Install dependencies:**
   ```bash
   poetry install
   ```

2. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Run tests:**
   ```bash
   poetry run pytest
   ```

## Architecture

The system is built with a modular architecture:

- **API Layer**: FastAPI endpoints with automatic validation
- **Service Layer**: Business logic and data processing
- **Data Layer**: SQLAlchemy models with async PostgreSQL
- **Authentication**: JWT-based with role and scope validation
- **Caching**: Redis for session management and performance

## Testing

The project includes comprehensive testing with Docker containerization:

- **Unit Tests**: Individual component testing
- **Integration Tests**: Database and Redis integration
- **Security Tests**: Authentication and authorization validation
- **Performance Tests**: Load and stress testing

## Documentation

- [Installation Guide](docs/getting-started/installation.md)
- [Configuration](docs/getting-started/configuration.md)
- [API Documentation](docs/api/)
- [Security Guide](docs/security/security-guide.md)
- [Development Guide](docs/development/)

## License

This project is licensed under the MIT License.