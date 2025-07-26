"""Main FastAPI application module for Keystone authentication system."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.config.database import init_db, close_db
from app.config.redis import init_redis, close_redis
from app.config.settings import settings


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


# Include routers (will be added as we implement endpoints)
# from app.api.v1.auth import router as auth_router
# from app.api.v1.users import router as users_router
# from app.api.v1.clients import router as clients_router

# app.include_router(auth_router, prefix="/api/v1/auth", tags=["authentication"])
# app.include_router(users_router, prefix="/api/v1/users", tags=["users"])
# app.include_router(clients_router, prefix="/api/v1/clients", tags=["clients"])