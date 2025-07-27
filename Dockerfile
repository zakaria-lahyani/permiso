# Multi-stage Dockerfile for permiso Authentication System
# Supports development, testing, and production environments

# Base stage with common dependencies
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry==1.7.1

# Configure Poetry
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VENV_IN_PROJECT=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

# Set work directory
WORKDIR /app

# Copy Poetry files
COPY pyproject.toml poetry.lock ./

# Development stage
FROM base as development

# Install all dependencies including dev dependencies
RUN poetry install --with dev && rm -rf $POETRY_CACHE_DIR

# Copy application code
COPY . .

# Create non-root user
RUN groupadd -r permiso && useradd -r -g permiso permiso
RUN chown -R permiso:permiso /app
USER permiso

# Expose port
EXPOSE 8000

# Command for development with hot reload
CMD ["poetry", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Testing stage
FROM base as testing

# Install all dependencies including dev and test dependencies
RUN poetry install --with dev,test && rm -rf $POETRY_CACHE_DIR

# Copy application code
COPY . .

# Create non-root user
RUN groupadd -r permiso && useradd -r -g permiso permiso
RUN chown -R permiso:permiso /app
USER permiso

# Set testing environment
ENV ENVIRONMENT=testing

# Command for running tests
CMD ["poetry", "run", "pytest", "tests/", "-v", "--tb=short", "--cov=app", "--cov-report=term-missing", "--cov-report=html", "--cov-fail-under=80"]

# Production stage
FROM base as production

# Install only production dependencies
RUN poetry install --only=main && rm -rf $POETRY_CACHE_DIR

# Copy application code
COPY . .

# Create non-root user
RUN groupadd -r permiso && useradd -r -g permiso permiso
RUN chown -R permiso:permiso /app
USER permiso

# Set production environment
ENV ENVIRONMENT=production

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Command for production
CMD ["poetry", "run", "gunicorn", "app.main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]