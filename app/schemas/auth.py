"""Authentication-related Pydantic schemas for API request/response models."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class TokenRequest(BaseModel):
    """Schema for OAuth2 token request."""
    username: str = Field(..., description="Username or email")
    password: str = Field(..., description="User password")
    scope: Optional[str] = Field(None, description="Requested scopes (space-separated)")


class ServiceTokenRequest(BaseModel):
    """Schema for service token request."""
    client_id: str = Field(..., description="Service client ID")
    client_secret: str = Field(..., description="Service client secret")
    scope: Optional[str] = Field(None, description="Requested scopes (space-separated)")


class TokenResponse(BaseModel):
    """Schema for token response."""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field("Bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    refresh_token: Optional[str] = Field(None, description="JWT refresh token")
    scope: Optional[str] = Field(None, description="Granted scopes (space-separated)")
    session_id: Optional[str] = Field(None, description="Session ID for session management")


class RefreshTokenRequest(BaseModel):
    """Schema for refresh token request."""
    refresh_token: str = Field(..., description="Refresh token")


class TokenIntrospectionRequest(BaseModel):
    """Schema for token introspection request."""
    token: str = Field(..., description="Token to introspect")
    token_type_hint: Optional[str] = Field(None, description="Hint about token type")


class TokenIntrospectionResponse(BaseModel):
    """Schema for token introspection response."""
    active: bool = Field(..., description="Whether the token is active")
    sub: Optional[str] = Field(None, description="Subject (user ID or client ID)")
    username: Optional[str] = Field(None, description="Username (for user tokens)")
    client_id: Optional[str] = Field(None, description="Client ID (for service tokens)")
    scope: Optional[str] = Field(None, description="Token scopes")
    exp: Optional[int] = Field(None, description="Expiration timestamp")
    iat: Optional[int] = Field(None, description="Issued at timestamp")
    token_type: Optional[str] = Field(None, description="Token type")


class TokenRevocationRequest(BaseModel):
    """Schema for token revocation request."""
    token: str = Field(..., description="Token to revoke")
    token_type_hint: Optional[str] = Field(None, description="Hint about token type")


class LoginAttempt(BaseModel):
    """Schema for login attempt logging."""
    username: str
    ip_address: str
    user_agent: Optional[str] = None
    success: bool
    failure_reason: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True


class AuthStats(BaseModel):
    """Schema for authentication statistics."""
    total_logins_today: int
    failed_logins_today: int
    active_sessions: int
    locked_accounts: int
    recent_registrations: int


class SessionInfo(BaseModel):
    """Schema for session information."""
    session_id: str
    user_id: int
    username: str
    ip_address: str
    user_agent: Optional[str] = None
    created_at: datetime
    last_activity: datetime
    expires_at: datetime

    class Config:
        from_attributes = True


class ActiveSessionsResponse(BaseModel):
    """Schema for active sessions response."""
    sessions: List[SessionInfo]
    total: int


class LogoutRequest(BaseModel):
    """Schema for logout request."""
    all_sessions: bool = Field(False, description="Logout from all sessions")


class LogoutResponse(BaseModel):
    """Schema for logout response."""
    message: str = Field(..., description="Logout confirmation message")
    sessions_terminated: int = Field(..., description="Number of sessions terminated")


class AuthError(BaseModel):
    """Schema for authentication error responses."""
    error: str = Field(..., description="Error code")
    error_description: str = Field(..., description="Human-readable error description")
    error_uri: Optional[str] = Field(None, description="URI for more information")


class RateLimitInfo(BaseModel):
    """Schema for rate limit information."""
    limit: int = Field(..., description="Rate limit threshold")
    remaining: int = Field(..., description="Remaining requests")
    reset_time: datetime = Field(..., description="When the rate limit resets")
    retry_after: Optional[int] = Field(None, description="Seconds to wait before retry")


class SecurityEvent(BaseModel):
    """Schema for security event logging."""
    event_type: str = Field(..., description="Type of security event")
    user_id: Optional[int] = Field(None, description="User ID if applicable")
    client_id: Optional[str] = Field(None, description="Client ID if applicable")
    ip_address: str = Field(..., description="Source IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    details: Optional[dict] = Field(None, description="Additional event details")
    severity: str = Field(..., description="Event severity level")
    timestamp: datetime = Field(..., description="Event timestamp")

    class Config:
        from_attributes = True


class SecurityEventsResponse(BaseModel):
    """Schema for security events response."""
    events: List[SecurityEvent]
    total: int
    page: int
    per_page: int


class TwoFactorSetupRequest(BaseModel):
    """Schema for two-factor authentication setup."""
    method: str = Field(..., description="2FA method (totp, sms, email)")
    phone_number: Optional[str] = Field(None, description="Phone number for SMS")


class TwoFactorSetupResponse(BaseModel):
    """Schema for two-factor authentication setup response."""
    secret: Optional[str] = Field(None, description="TOTP secret key")
    qr_code: Optional[str] = Field(None, description="QR code for TOTP setup")
    backup_codes: List[str] = Field(default=[], description="Backup recovery codes")


class TwoFactorVerifyRequest(BaseModel):
    """Schema for two-factor authentication verification."""
    code: str = Field(..., description="2FA verification code")
    method: Optional[str] = Field(None, description="2FA method used")


class TwoFactorVerifyResponse(BaseModel):
    """Schema for two-factor authentication verification response."""
    verified: bool = Field(..., description="Whether verification was successful")
    message: str = Field(..., description="Verification result message")


class DeviceInfo(BaseModel):
    """Schema for device information."""
    device_id: str = Field(..., description="Unique device identifier")
    device_name: str = Field(..., description="Human-readable device name")
    device_type: str = Field(..., description="Device type (mobile, desktop, etc.)")
    os: Optional[str] = Field(None, description="Operating system")
    browser: Optional[str] = Field(None, description="Browser information")
    ip_address: str = Field(..., description="Device IP address")
    last_seen: datetime = Field(..., description="Last activity timestamp")
    is_trusted: bool = Field(False, description="Whether device is trusted")

    class Config:
        from_attributes = True


class TrustedDevicesResponse(BaseModel):
    """Schema for trusted devices response."""
    devices: List[DeviceInfo]
    total: int


class DeviceTrustRequest(BaseModel):
    """Schema for device trust management."""
    device_id: str = Field(..., description="Device ID to trust/untrust")
    trusted: bool = Field(..., description="Whether to trust the device")


class ApiKeyCreate(BaseModel):
    """Schema for API key creation."""
    name: str = Field(..., max_length=100, description="API key name")
    description: Optional[str] = Field(None, max_length=500, description="API key description")
    scopes: List[str] = Field(default=[], description="API key scopes")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")


class ApiKeyResponse(BaseModel):
    """Schema for API key response."""
    id: int
    name: str
    description: Optional[str] = None
    key_prefix: str = Field(..., description="First 8 characters of the key")
    scopes: List[str] = []
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    is_active: bool

    class Config:
        from_attributes = True


class ApiKeyCreateResponse(BaseModel):
    """Schema for API key creation response."""
    api_key: ApiKeyResponse
    secret_key: str = Field(..., description="Full API key (only shown once)")


class ApiKeysResponse(BaseModel):
    """Schema for API keys list response."""
    api_keys: List[ApiKeyResponse]
    total: int