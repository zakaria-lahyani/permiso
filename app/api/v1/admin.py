"""Administrative functions API endpoints for permiso authentication system."""

from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text, and_, or_

from app.config.database import get_db
from app.config.redis import get_redis
from app.core.security import require_admin, require_scopes
from app.models.user import User
from app.models.role import Role
from app.models.scope import Scope
from app.models.service_client import ServiceClient
from app.schemas.auth import AuthStats, SecurityEvent, SecurityEventsResponse
from app.schemas.user import UserStats
from app.schemas.role import RoleStats
from app.schemas.service_client import ServiceClientStats

router = APIRouter()


@router.get("/dashboard/stats")
async def get_dashboard_stats(
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis)
):
    """
    Get comprehensive dashboard statistics.
    
    Requires admin role.
    """
    try:
        # User statistics
        total_users = await db.execute(select(func.count(User.id)))
        active_users = await db.execute(
            select(func.count(User.id)).where(User.is_active == True)
        )
        verified_users = await db.execute(
            select(func.count(User.id)).where(User.is_verified == True)
        )
        locked_users = await db.execute(
            select(func.count(User.id)).where(User.locked_until > datetime.utcnow())
        )
        
        # Role statistics
        total_roles = await db.execute(select(func.count(Role.id)))
        total_scopes = await db.execute(select(func.count(Scope.id)))
        
        # Service client statistics
        total_clients = await db.execute(select(func.count(ServiceClient.id)))
        active_clients = await db.execute(
            select(func.count(ServiceClient.id)).where(ServiceClient.is_active == True)
        )
        
        # Authentication statistics (mock data from Redis)
        try:
            today_key = f"successful_login:{datetime.utcnow().strftime('%Y-%m-%d')}"
            total_logins_today = await redis.get(today_key) or 0
            if isinstance(total_logins_today, bytes):
                total_logins_today = int(total_logins_today.decode())
            elif isinstance(total_logins_today, str):
                total_logins_today = int(total_logins_today)
        except:
            total_logins_today = 0
        
        # Recent registrations (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_registrations = await db.execute(
            select(func.count(User.id)).where(User.created_at >= thirty_days_ago)
        )
        
        return {
            "users": {
                "total": total_users.scalar(),
                "active": active_users.scalar(),
                "verified": verified_users.scalar(),
                "locked": locked_users.scalar(),
                "recent_registrations": recent_registrations.scalar()
            },
            "roles_and_permissions": {
                "total_roles": total_roles.scalar(),
                "total_scopes": total_scopes.scalar()
            },
            "service_clients": {
                "total": total_clients.scalar(),
                "active": active_clients.scalar()
            },
            "authentication": {
                "total_logins_today": total_logins_today,
                "failed_logins_today": 0,  # Mock data
                "active_sessions": 0  # Mock data
            },
            "system": {
                "uptime_hours": 24,  # Mock data
                "last_backup": datetime.utcnow() - timedelta(hours=6),  # Mock data
                "database_size_mb": 150.5,  # Mock data
                "redis_memory_mb": 25.3  # Mock data
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/system/health")
async def get_system_health(
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis)
):
    """
    Get system health status.
    
    Requires admin role.
    """
    try:
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow(),
            "components": {}
        }
        
        # Database health
        try:
            await db.execute(text("SELECT 1"))
            health_status["components"]["database"] = {
                "status": "healthy",
                "response_time_ms": 5  # Mock data
            }
        except Exception as e:
            health_status["components"]["database"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            health_status["status"] = "degraded"
        
        # Redis health
        try:
            await redis.ping()
            health_status["components"]["redis"] = {
                "status": "healthy",
                "response_time_ms": 2  # Mock data
            }
        except Exception as e:
            health_status["components"]["redis"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            health_status["status"] = "degraded"
        
        # JWT service health (mock)
        health_status["components"]["jwt_service"] = {
            "status": "healthy",
            "tokens_issued_today": 150  # Mock data
        }
        
        # Overall system metrics
        health_status["metrics"] = {
            "memory_usage_percent": 65.2,  # Mock data
            "cpu_usage_percent": 23.1,  # Mock data
            "disk_usage_percent": 45.8,  # Mock data
            "active_connections": 12  # Mock data
        }
        
        return health_status
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/security/events", response_model=SecurityEventsResponse)
async def get_security_events(
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    current_user = Depends(require_scopes(["admin:security"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get security events log.
    
    Requires admin:security scope.
    """
    try:
        # Mock security events data
        # In a real implementation, this would query a security events table
        mock_events = [
            SecurityEvent(
                event_type="failed_login",
                user_id=None,
                client_id=None,
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0...",
                details={"username": "admin", "attempts": 3},
                severity="medium",
                timestamp=datetime.utcnow() - timedelta(minutes=30)
            ),
            SecurityEvent(
                event_type="suspicious_activity",
                user_id=123,
                client_id=None,
                ip_address="10.0.0.50",
                user_agent="curl/7.68.0",
                details={"action": "rapid_requests", "count": 100},
                severity="high",
                timestamp=datetime.utcnow() - timedelta(hours=2)
            ),
            SecurityEvent(
                event_type="token_revoked",
                user_id=456,
                client_id=None,
                ip_address="172.16.0.10",
                user_agent="PostmanRuntime/7.28.4",
                details={"reason": "admin_action"},
                severity="low",
                timestamp=datetime.utcnow() - timedelta(hours=4)
            )
        ]
        
        # Apply filters
        filtered_events = mock_events
        if event_type:
            filtered_events = [e for e in filtered_events if e.event_type == event_type]
        if severity:
            filtered_events = [e for e in filtered_events if e.severity == severity]
        
        # Apply time filter
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        filtered_events = [e for e in filtered_events if e.timestamp >= cutoff_time]
        
        # Apply pagination
        total = len(filtered_events)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_events = filtered_events[start_idx:end_idx]
        
        return SecurityEventsResponse(
            events=paginated_events,
            total=total,
            page=page,
            per_page=per_page
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.post("/maintenance/cleanup")
async def cleanup_expired_data(
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis)
):
    """
    Clean up expired data from the system.
    
    Requires admin role.
    """
    try:
        cleanup_results = {
            "timestamp": datetime.utcnow(),
            "operations": []
        }
        
        # Clean up expired refresh tokens
        from app.models.refresh_token import RefreshToken
        expired_tokens_result = await db.execute(
            select(func.count(RefreshToken.id)).where(
                RefreshToken.expires_at < datetime.utcnow()
            )
        )
        expired_tokens_count = expired_tokens_result.scalar()
        
        if expired_tokens_count > 0:
            await db.execute(
                text("DELETE FROM refresh_tokens WHERE expires_at < :now"),
                {"now": datetime.utcnow()}
            )
            cleanup_results["operations"].append({
                "operation": "cleanup_expired_refresh_tokens",
                "items_removed": expired_tokens_count
            })
        
        # Clean up expired password reset tokens
        reset_tokens_result = await db.execute(
            select(func.count(User.id)).where(
                and_(
                    User.password_reset_token.isnot(None),
                    User.password_reset_sent_at < datetime.utcnow() - timedelta(hours=24)
                )
            )
        )
        reset_tokens_count = reset_tokens_result.scalar()
        
        if reset_tokens_count > 0:
            await db.execute(
                text("""
                    UPDATE users 
                    SET password_reset_token = NULL, password_reset_sent_at = NULL 
                    WHERE password_reset_token IS NOT NULL 
                    AND password_reset_sent_at < :cutoff
                """),
                {"cutoff": datetime.utcnow() - timedelta(hours=24)}
            )
            cleanup_results["operations"].append({
                "operation": "cleanup_expired_password_reset_tokens",
                "items_removed": reset_tokens_count
            })
        
        # Clean up expired email verification tokens
        verification_tokens_result = await db.execute(
            select(func.count(User.id)).where(
                and_(
                    User.email_verification_token.isnot(None),
                    User.email_verification_sent_at < datetime.utcnow() - timedelta(hours=48)
                )
            )
        )
        verification_tokens_count = verification_tokens_result.scalar()
        
        if verification_tokens_count > 0:
            await db.execute(
                text("""
                    UPDATE users 
                    SET email_verification_token = NULL, email_verification_sent_at = NULL 
                    WHERE email_verification_token IS NOT NULL 
                    AND email_verification_sent_at < :cutoff
                """),
                {"cutoff": datetime.utcnow() - timedelta(hours=48)}
            )
            cleanup_results["operations"].append({
                "operation": "cleanup_expired_email_verification_tokens",
                "items_removed": verification_tokens_count
            })
        
        # Unlock accounts that have passed their lockout period
        locked_users_result = await db.execute(
            select(func.count(User.id)).where(
                and_(
                    User.locked_until.isnot(None),
                    User.locked_until < datetime.utcnow()
                )
            )
        )
        locked_users_count = locked_users_result.scalar()
        
        if locked_users_count > 0:
            await db.execute(
                text("""
                    UPDATE users 
                    SET locked_until = NULL, failed_login_attempts = 0 
                    WHERE locked_until IS NOT NULL 
                    AND locked_until < :now
                """),
                {"now": datetime.utcnow()}
            )
            cleanup_results["operations"].append({
                "operation": "unlock_expired_accounts",
                "items_processed": locked_users_count
            })
        
        # Clean up old Redis keys (mock operation)
        try:
            # In a real implementation, you would scan for expired keys
            cleanup_results["operations"].append({
                "operation": "cleanup_redis_expired_keys",
                "items_removed": 25  # Mock data
            })
        except Exception:
            pass
        
        await db.commit()
        
        return cleanup_results
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.post("/maintenance/backup")
async def create_system_backup(
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a system backup.
    
    Requires admin role.
    """
    try:
        # Mock backup operation
        # In a real implementation, this would trigger actual backup processes
        
        backup_info = {
            "backup_id": f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            "timestamp": datetime.utcnow(),
            "status": "initiated",
            "components": {
                "database": {
                    "status": "pending",
                    "estimated_size_mb": 150.5
                },
                "redis": {
                    "status": "pending", 
                    "estimated_size_mb": 25.3
                },
                "configuration": {
                    "status": "pending",
                    "estimated_size_mb": 0.5
                }
            },
            "estimated_duration_minutes": 15,
            "backup_location": "/backups/system/"
        }
        
        return backup_info
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/audit/activity")
async def get_audit_activity(
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    current_user = Depends(require_scopes(["admin:audit"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get audit activity log.
    
    Requires admin:audit scope.
    """
    try:
        # Mock audit activity data
        # In a real implementation, this would query an audit log table
        mock_activities = [
            {
                "id": 1,
                "user_id": 123,
                "username": "admin_user",
                "action": "user_created",
                "resource_type": "user",
                "resource_id": 456,
                "details": {"created_user": "new_user", "roles": ["user"]},
                "ip_address": "192.168.1.10",
                "user_agent": "Mozilla/5.0...",
                "timestamp": datetime.utcnow() - timedelta(minutes=15)
            },
            {
                "id": 2,
                "user_id": 123,
                "username": "admin_user", 
                "action": "role_updated",
                "resource_type": "role",
                "resource_id": 2,
                "details": {"role_name": "moderator", "scopes_added": ["read:posts"]},
                "ip_address": "192.168.1.10",
                "user_agent": "Mozilla/5.0...",
                "timestamp": datetime.utcnow() - timedelta(hours=1)
            },
            {
                "id": 3,
                "user_id": 789,
                "username": "service_admin",
                "action": "client_created",
                "resource_type": "service_client",
                "resource_id": "new-api-client",
                "details": {"client_name": "New API Client", "scopes": ["api:read"]},
                "ip_address": "10.0.0.5",
                "user_agent": "curl/7.68.0",
                "timestamp": datetime.utcnow() - timedelta(hours=3)
            }
        ]
        
        # Apply filters
        filtered_activities = mock_activities
        if user_id:
            filtered_activities = [a for a in filtered_activities if a["user_id"] == user_id]
        if action:
            filtered_activities = [a for a in filtered_activities if a["action"] == action]
        
        # Apply time filter
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        filtered_activities = [a for a in filtered_activities if a["timestamp"] >= cutoff_time]
        
        # Apply pagination
        total = len(filtered_activities)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_activities = filtered_activities[start_idx:end_idx]
        
        return {
            "activities": paginated_activities,
            "total": total,
            "page": page,
            "per_page": per_page
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/reports/usage")
async def get_usage_report(
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Get system usage report.
    
    Requires admin role.
    """
    try:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # User activity
        new_users = await db.execute(
            select(func.count(User.id)).where(
                User.created_at >= start_date
            )
        )
        
        active_users = await db.execute(
            select(func.count(User.id)).where(
                and_(
                    User.last_login >= start_date,
                    User.is_active == True
                )
            )
        )
        
        # Mock API usage data
        api_usage = {
            "total_requests": 45000,
            "authentication_requests": 12000,
            "user_management_requests": 8000,
            "service_client_requests": 25000,
            "average_response_time_ms": 125.5,
            "error_rate_percent": 0.8
        }
        
        # Mock popular endpoints
        popular_endpoints = [
            {"endpoint": "/api/v1/auth/token", "requests": 12000, "avg_response_ms": 95},
            {"endpoint": "/api/v1/users/me", "requests": 8500, "avg_response_ms": 45},
            {"endpoint": "/api/v1/auth/refresh", "requests": 6200, "avg_response_ms": 80},
            {"endpoint": "/api/v1/service-clients", "requests": 3400, "avg_response_ms": 150},
            {"endpoint": "/api/v1/roles", "requests": 2100, "avg_response_ms": 120}
        ]
        
        return {
            "report_period": {
                "start_date": start_date,
                "end_date": end_date,
                "days": days
            },
            "user_activity": {
                "new_users": new_users.scalar(),
                "active_users": active_users.scalar()
            },
            "api_usage": api_usage,
            "popular_endpoints": popular_endpoints,
            "system_performance": {
                "uptime_percent": 99.95,
                "average_cpu_percent": 25.3,
                "average_memory_percent": 68.7,
                "database_size_growth_mb": 15.2
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.post("/config/reload")
async def reload_configuration(
    current_user = Depends(require_scopes(["admin:system"])),
):
    """
    Reload system configuration.
    
    Requires admin:system scope.
    """
    try:
        # Mock configuration reload
        # In a real implementation, this would reload configuration from files/environment
        
        reload_info = {
            "timestamp": datetime.utcnow(),
            "status": "success",
            "components_reloaded": [
                "database_settings",
                "redis_settings", 
                "jwt_settings",
                "security_settings",
                "rate_limiting_settings"
            ],
            "warnings": [],
            "errors": []
        }
        
        return reload_info
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/logs/errors")
async def get_error_logs(
    level: str = Query("ERROR", description="Log level filter"),
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    current_user = Depends(require_scopes(["admin:logs"])),
):
    """
    Get system error logs.
    
    Requires admin:logs scope.
    """
    try:
        # Mock error logs data
        # In a real implementation, this would read from log files or logging service
        
        mock_logs = [
            {
                "timestamp": datetime.utcnow() - timedelta(minutes=30),
                "level": "ERROR",
                "logger": "app.api.v1.auth",
                "message": "Failed to authenticate user: invalid credentials",
                "details": {
                    "user_id": None,
                    "ip_address": "192.168.1.100",
                    "error_code": "AUTH001"
                }
            },
            {
                "timestamp": datetime.utcnow() - timedelta(hours=2),
                "level": "WARNING",
                "logger": "app.core.security",
                "message": "Rate limit exceeded for IP address",
                "details": {
                    "ip_address": "10.0.0.50",
                    "endpoint": "/api/v1/auth/token",
                    "attempts": 15
                }
            },
            {
                "timestamp": datetime.utcnow() - timedelta(hours=4),
                "level": "ERROR",
                "logger": "app.config.database",
                "message": "Database connection timeout",
                "details": {
                    "timeout_seconds": 30,
                    "retry_attempt": 3
                }
            }
        ]
        
        # Apply filters
        filtered_logs = mock_logs
        if level != "ALL":
            filtered_logs = [log for log in filtered_logs if log["level"] == level]
        
        # Apply time filter
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        filtered_logs = [log for log in filtered_logs if log["timestamp"] >= cutoff_time]
        
        # Apply pagination
        total = len(filtered_logs)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_logs = filtered_logs[start_idx:end_idx]
        
        return {
            "logs": paginated_logs,
            "total": total,
            "page": page,
            "per_page": per_page,
            "available_levels": ["ERROR", "WARNING", "INFO", "DEBUG"]
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )