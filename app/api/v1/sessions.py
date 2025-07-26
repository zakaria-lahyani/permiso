"""Session management API endpoints."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.database import get_db
from app.config.redis import get_redis
from app.core.security import get_current_user, require_scopes
from app.models.user import User
from app.services.session_service import SessionService, get_session_service
from app.schemas.auth import SessionInfo, ActiveSessionsResponse

router = APIRouter()


@router.get("/", response_model=ActiveSessionsResponse)
async def get_user_sessions(
    current_user = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
    db: AsyncSession = Depends(get_db),
):
    """
    Get all active sessions for the current user.
    
    Returns list of active sessions with metadata.
    """
    try:
        sessions = await session_service.get_user_sessions(current_user.id)
        
        session_info_list = []
        for session in sessions:
            session_info = SessionInfo(
                session_id=session.session_id,
                user_id=int(session.user_id),
                username=current_user.username,
                ip_address=session.ip_address,
                user_agent=session.user_agent,
                created_at=session.created_at,
                last_activity=session.last_activity,
                expires_at=session.expires_at,
            )
            session_info_list.append(session_info)
        
        return ActiveSessionsResponse(
            sessions=session_info_list,
            total=len(session_info_list)
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": "Failed to retrieve sessions"}
        )


@router.post("/{session_id}/renew")
async def renew_session(
    session_id: str,
    current_user = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
):
    """
    Renew a specific session.
    
    Extends the session expiry time.
    """
    try:
        # Verify the session belongs to the current user
        session = await session_service.get_session(session_id)
        
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "session_not_found", "error_description": "Session not found"}
            )
        
        if session.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "access_denied", "error_description": "Access denied to this session"}
            )
        
        renewed_session = await session_service.renew_session(session_id)
        
        if not renewed_session:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "renewal_failed", "error_description": "Session renewal failed"}
            )
        
        return {
            "message": "Session renewed successfully",
            "session_id": session_id,
            "expires_at": renewed_session.expires_at.isoformat(),
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": "Session renewal failed"}
        )


@router.delete("/{session_id}")
async def invalidate_session(
    session_id: str,
    current_user = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
):
    """
    Invalidate a specific session.
    
    Terminates the session immediately.
    """
    try:
        # Verify the session belongs to the current user
        session = await session_service.get_session(session_id)
        
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "session_not_found", "error_description": "Session not found"}
            )
        
        if session.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "access_denied", "error_description": "Access denied to this session"}
            )
        
        success = await session_service.invalidate_session(session_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalidation_failed", "error_description": "Session invalidation failed"}
            )
        
        return {
            "message": "Session invalidated successfully",
            "session_id": session_id,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": "Session invalidation failed"}
        )


@router.delete("/")
async def invalidate_all_sessions(
    current_user = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
):
    """
    Invalidate all sessions for the current user.
    
    Terminates all active sessions except the current one.
    """
    try:
        count = await session_service.invalidate_all_user_sessions(current_user.id)
        
        return {
            "message": "All sessions invalidated successfully",
            "sessions_terminated": count,
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": "Session invalidation failed"}
        )


@router.get("/stats", dependencies=[Depends(require_scopes(["admin:sessions"]))])
async def get_session_stats(
    session_service: SessionService = Depends(get_session_service),
):
    """
    Get session statistics.
    
    Requires admin:sessions scope.
    """
    try:
        stats = await session_service.get_session_stats()
        return stats
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": "Failed to retrieve session statistics"}
        )


@router.post("/cleanup", dependencies=[Depends(require_scopes(["admin:sessions"]))])
async def cleanup_expired_sessions(
    session_service: SessionService = Depends(get_session_service),
):
    """
    Clean up expired sessions.
    
    Requires admin:sessions scope.
    """
    try:
        count = await session_service.cleanup_expired_sessions()
        
        return {
            "message": "Expired sessions cleaned up successfully",
            "sessions_cleaned": count,
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": "Session cleanup failed"}
        )