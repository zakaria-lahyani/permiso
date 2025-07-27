"""Audit logging functionality for security events."""

import logging
from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from app.config.settings import settings


class AuditLogger:
    """Audit logger with methods for different event types."""
    
    def __init__(self):
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)
        
        # Create handler if not exists
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - AUDIT - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def log_security_event(
        self,
        event_type: str,
        severity: str = "INFO",
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log general security events."""
        event = AuditEvent(
            event_type=event_type,
            user_id=user_id,
            username=username,
            resource=resource,
            action=action,
            result=severity,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details
        )
        
        log_method = getattr(self.logger, severity.lower(), self.logger.info)
        log_method(f"SECURITY_EVENT: {event.to_dict()}")
    
    def log_authentication_event(
        self,
        event_type: str,
        username: str,
        result: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log authentication-related events."""
        event = AuditEvent(
            event_type=event_type,
            user_id=user_id,
            username=username,
            action="authenticate",
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details
        )
        
        self.logger.info(f"AUTH_EVENT: {event.to_dict()}")


# Create global audit logger instance
audit_logger = AuditLogger()


class AuditEvent:
    """Audit event data structure."""
    
    def __init__(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.timestamp = datetime.utcnow()
        self.event_type = event_type
        self.user_id = user_id
        self.username = username
        self.resource = resource
        self.action = action
        self.result = result
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "user_id": self.user_id,
            "username": self.username,
            "resource": self.resource,
            "action": self.action,
            "result": self.result,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "details": self.details
        }


def log_authentication_event(
    event_type: str,
    username: str,
    result: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log authentication-related events.
    
    Args:
        event_type: Type of authentication event
        username: Username involved
        result: Result of the event (success, failure, etc.)
        user_id: User ID if available
        ip_address: Client IP address
        user_agent: Client user agent
        details: Additional event details
    """
    audit_logger.log_authentication_event(
        event_type=event_type,
        username=username,
        result=result,
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details
    )


def log_authorization_event(
    event_type: str,
    user_id: str,
    username: str,
    resource: str,
    action: str,
    result: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log authorization-related events.
    
    Args:
        event_type: Type of authorization event
        user_id: User ID
        username: Username
        resource: Resource being accessed
        action: Action being performed
        result: Result of the authorization check
        ip_address: Client IP address
        user_agent: Client user agent
        details: Additional event details
    """
    # Use log_security_event since AuditLogger doesn't have log_authorization_event method
    audit_logger.log_security_event(
        event_type=event_type,
        severity="INFO",
        user_id=user_id,
        username=username,
        resource=resource,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details
    )


def log_security_event(
    event_type: str,
    severity: str = "INFO",
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    resource: Optional[str] = None,
    action: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log general security events.
    
    Args:
        event_type: Type of security event
        severity: Event severity level
        user_id: User ID if applicable
        username: Username if applicable
        resource: Resource involved if applicable
        action: Action involved if applicable
        ip_address: Client IP address
        user_agent: Client user agent
        details: Additional event details
    """
    audit_logger.log_security_event(
        event_type=event_type,
        severity=severity,
        user_id=user_id,
        username=username,
        resource=resource,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details
    )


def log_failed_login(
    username: str,
    reason: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> None:
    """Log failed login attempt."""
    log_authentication_event(
        event_type="login_failed",
        username=username,
        result="failure",
        ip_address=ip_address,
        user_agent=user_agent,
        details={"reason": reason}
    )


def log_successful_login(
    user_id: str,
    username: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> None:
    """Log successful login."""
    log_authentication_event(
        event_type="login_success",
        username=username,
        result="success",
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent
    )


def log_authorization_failure(
    user_id: str,
    username: str,
    resource: str,
    action: str,
    reason: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> None:
    """Log authorization failure."""
    log_authorization_event(
        event_type="authorization_denied",
        user_id=user_id,
        username=username,
        resource=resource,
        action=action,
        result="denied",
        ip_address=ip_address,
        user_agent=user_agent,
        details={"reason": reason}
    )


def log_privilege_escalation_attempt(
    user_id: str,
    username: str,
    attempted_resource: str,
    attempted_action: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> None:
    """Log privilege escalation attempt."""
    log_security_event(
        event_type="privilege_escalation_attempt",
        severity="WARNING",
        user_id=user_id,
        username=username,
        resource=attempted_resource,
        action=attempted_action,
        ip_address=ip_address,
        user_agent=user_agent,
        details={"threat_level": "high"}
    )