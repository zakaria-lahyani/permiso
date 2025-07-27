"""Main FastAPI application module for Keystone authentication system."""

import json
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.config.database import init_db, close_db
from app.config.redis import init_redis, close_redis
from app.config.settings import settings
from app.core.json import CustomJSONEncoder, custom_json_serializer


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    await init_db()
    await init_redis()
    
    yield
    
    # Shutdown
    await close_db()
    await close_redis()


# Create FastAPI application
app = FastAPI(
    title="Keystone Authentication System",
    description="Centralized authentication and authorization system",
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
    redirect_slashes=False,
)

# Configure custom JSON encoder for all responses
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse as FastAPIJSONResponse

class CustomJSONResponse(FastAPIJSONResponse):
    """Custom JSON response that uses our custom encoder."""
    
    def render(self, content) -> bytes:
        return custom_json_serializer(content).encode("utf-8")

# Set as default response class
app.router.default_response_class = CustomJSONResponse

# Add custom exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors properly."""
    content = {
        "error": "validation_error",
        "error_description": "Request validation failed",
        "details": exc.errors()
    }
    return CustomJSONResponse(
        status_code=422,
        content=content
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions properly."""
    content = exc.detail if isinstance(exc.detail, dict) else {
        "error": "http_error",
        "error_description": str(exc.detail)
    }
    return CustomJSONResponse(
        status_code=exc.status_code,
        content=content
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions with proper JSON serialization."""
    content = {
        "error": "internal_server_error",
        "error_description": "An internal server error occurred",
        "details": {
            "type": exc.__class__.__name__,
            "message": str(exc)
        }
    }
    return CustomJSONResponse(
        status_code=500,
        content=content
    )

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS,
)


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    
    # Security headers
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["x-frame-options"] = "DENY"
    response.headers["x-xss-protection"] = "1; mode=block"
    response.headers["referrer-policy"] = "strict-origin-when-cross-origin"
    response.headers["permissions-policy"] = "geolocation=(), microphone=(), camera=()"
    
    # Only add HSTS in production with HTTPS
    if not settings.DEBUG and request.url.scheme == "https":
        response.headers["strict-transport-security"] = "max-age=31536000; includeSubDomains"
    
    return response


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "keystone-auth",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
    }


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "message": "Keystone Authentication System",
        "version": "1.0.0",
        "docs": "/docs" if settings.DEBUG else "Documentation disabled in production",
        "health": "/health",
    }


# Include API routers
from app.api.v1.auth import router as auth_router
from app.api.v1.users import router as users_router
from app.api.v1.roles import router as roles_router
from app.api.v1.service_clients import router as service_clients_router
from app.api.v1.admin import router as admin_router
from app.api.v1.sessions import router as sessions_router

app.include_router(auth_router, prefix="/api/v1/auth", tags=["authentication"])
app.include_router(users_router, prefix="/api/v1/users", tags=["users"])
app.include_router(roles_router, prefix="/api/v1/roles", tags=["roles"])
app.include_router(service_clients_router, prefix="/api/v1/service-clients", tags=["service-clients"])
app.include_router(admin_router, prefix="/api/v1/admin", tags=["administration"])
app.include_router(sessions_router, prefix="/api/v1/sessions", tags=["sessions"])