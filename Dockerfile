# Multi-stage production-ready Dockerfile for Permiso Authentication System
# Optimized for cross-platform builds (AMD64/ARM64) and cloud deployment

# =============================================================================
# Base Stage - Common dependencies and setup
# =============================================================================
FROM python:3.11-slim AS base

# Set environment variables for Python
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VENV_IN_PROJECT=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache \
    POETRY_VIRTUALENVS_PATH=/app/.venv \
    POETRY_VIRTUALENVS_CREATE=true \
    POETRY_VIRTUALENVS_IN_PROJECT=true

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    libpq-dev \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Poetry
RUN pip install poetry==1.7.1

# Create app directory and non-root user
RUN groupadd -r permiso && useradd -r -g permiso -d /app -s /bin/bash permiso
WORKDIR /app

# Copy dependency files, README, and source code for project installation
COPY pyproject.toml poetry.lock* README.md ./
COPY app ./app
RUN chown -R permiso:permiso /app

# =============================================================================
# Dependencies Stage - Install Python dependencies
# =============================================================================
FROM base AS dependencies

# Install dependencies based on target
ARG INSTALL_DEV=false
RUN if [ "$INSTALL_DEV" = "true" ] ; then \
        poetry install --with dev ; \
    else \
        poetry install --only=main ; \
    fi && \
    rm -rf $POETRY_CACHE_DIR

# =============================================================================
# Development Stage - For local development with hot reload
# =============================================================================
FROM dependencies AS development

# Copy application code (project already installed in dependencies stage)
COPY --chown=permiso:permiso . .

# Create directories for development
RUN mkdir -p /app/logs /app/test-reports /app/htmlcov && \
    chown -R permiso:permiso /app

# Switch to non-root user
USER permiso

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Development command with hot reload
CMD ["poetry", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# =============================================================================
# Testing Stage - For running tests in CI/CD
# =============================================================================
FROM dependencies AS testing

# Copy application code (project already installed in dependencies stage)
COPY --chown=permiso:permiso . .

# Create test directories
RUN mkdir -p /app/test-reports /app/htmlcov && \
    chown -R permiso:permiso /app

# Switch to non-root user
USER permiso

# Set testing environment
ENV ENVIRONMENT=testing

# Test command
CMD ["poetry", "run", "pytest", "tests/", "-v", "--tb=short", "--cov=app", "--cov-report=term-missing", "--cov-report=html", "--cov-fail-under=80"]

# =============================================================================
# Production Stage - Optimized for production deployment
# =============================================================================
FROM python:3.11-slim AS production

# Set production environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ENVIRONMENT=production

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd -r permiso && useradd -r -g permiso -d /app -s /bin/bash permiso

# Set working directory
WORKDIR /app

# Copy virtual environment from dependencies stage
COPY --from=dependencies --chown=permiso:permiso /app/.venv /app/.venv

# Copy application code
COPY --chown=permiso:permiso . .

# Create necessary directories
RUN mkdir -p /app/logs && \
    chown -R permiso:permiso /app

# Switch to non-root user
USER permiso

# Add virtual environment to PATH
ENV PATH="/app/.venv/bin:$PATH"

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Production command with Gunicorn
CMD ["gunicorn", "app.main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--access-logfile", "-", "--error-logfile", "-"]

# =============================================================================
# Migration Stage - For running database migrations
# =============================================================================
FROM production AS migration

# Migration command
CMD ["alembic", "upgrade", "head"]