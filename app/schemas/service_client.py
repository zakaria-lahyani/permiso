"""Service client-related Pydantic schemas for API request/response models."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, validator
import re


class ServiceClientBase(BaseModel):
    """Base service client schema with common fields."""
    name: str = Field(..., min_length=2, max_length=100, description="Human-readable client name")
    description: Optional[str] = Field(None, max_length=1000, description="Client description")
    client_type: str = Field("confidential", description="OAuth2 client type")
    is_active: bool = Field(True, description="Whether the client is active")
    is_trusted: bool = Field(False, description="Whether the client is trusted")
    contact_email: Optional[str] = Field(None, description="Contact email for the client owner")
    website_url: Optional[str] = Field(None, max_length=500, description="Website URL")

    @validator('client_type')
    def validate_client_type(cls, v):
        """Validate client type."""
        allowed_types = ['confidential', 'public']
        if v not in allowed_types:
            raise ValueError(f'Client type must be one of: {", ".join(allowed_types)}')
        return v


class ServiceClientCreate(ServiceClientBase):
    """Schema for creating a new service client."""
    client_id: Optional[str] = Field(None, description="Custom client ID (auto-generated if not provided)")
    client_secret: Optional[str] = Field(None, description="Custom client secret (auto-generated if not provided)")
    scope_ids: Optional[List[str]] = Field(default=[], description="List of scope IDs to assign")
    access_token_lifetime: int = Field(3600, ge=300, le=86400, description="Access token lifetime in seconds")
    refresh_token_lifetime: Optional[int] = Field(None, ge=3600, description="Refresh token lifetime in seconds")
    rate_limit_per_minute: int = Field(60, ge=1, le=1000, description="Requests per minute limit")
    rate_limit_per_hour: int = Field(1000, ge=60, le=100000, description="Requests per hour limit")
    allowed_ips: Optional[str] = Field(None, description="Comma-separated allowed IP addresses/ranges")
    webhook_url: Optional[str] = Field(None, max_length=500, description="Webhook URL for notifications")

    @validator('client_id')
    def validate_client_id(cls, v):
        """Validate client ID format."""
        if v and not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Client ID can only contain letters, numbers, underscores, and hyphens')
        return v

    @validator('allowed_ips')
    def validate_allowed_ips(cls, v):
        """Validate IP address format."""
        if v:
            ips = [ip.strip() for ip in v.split(',')]
            for ip in ips:
                if not re.match(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$|^\*$', ip):
                    raise ValueError(f'Invalid IP address format: {ip}')
        return v


class ServiceClientUpdate(BaseModel):
    """Schema for updating an existing service client."""
    name: Optional[str] = Field(None, min_length=2, max_length=100, description="Client name")
    description: Optional[str] = Field(None, max_length=1000, description="Client description")
    is_active: Optional[bool] = Field(None, description="Whether the client is active")
    is_trusted: Optional[bool] = Field(None, description="Whether the client is trusted")
    contact_email: Optional[str] = Field(None, description="Contact email")
    website_url: Optional[str] = Field(None, max_length=500, description="Website URL")
    scope_ids: Optional[List[str]] = Field(None, description="List of scope IDs to assign")
    access_token_lifetime: Optional[int] = Field(None, ge=300, le=86400, description="Access token lifetime")
    refresh_token_lifetime: Optional[int] = Field(None, ge=3600, description="Refresh token lifetime")
    rate_limit_per_minute: Optional[int] = Field(None, ge=1, le=1000, description="Requests per minute limit")
    rate_limit_per_hour: Optional[int] = Field(None, ge=60, le=100000, description="Requests per hour limit")
    allowed_ips: Optional[str] = Field(None, description="Comma-separated allowed IP addresses")
    webhook_url: Optional[str] = Field(None, max_length=500, description="Webhook URL")

    @validator('allowed_ips')
    def validate_allowed_ips(cls, v):
        """Validate IP address format."""
        if v:
            ips = [ip.strip() for ip in v.split(',')]
            for ip in ips:
                if not re.match(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$|^\*$', ip):
                    raise ValueError(f'Invalid IP address format: {ip}')
        return v


class ServiceClientSecretRotation(BaseModel):
    """Schema for service client secret rotation."""
    current_secret: str = Field(..., description="Current client secret for verification")


class ScopeInfo(BaseModel):
    """Scope information for service client responses."""
    id: str
    name: str
    description: Optional[str] = None
    resource: str
    action: str

    class Config:
        from_attributes = True


class ServiceClientResponse(BaseModel):
    """Schema for service client response."""
    id: str
    client_id: str
    name: str
    description: Optional[str] = None
    client_type: str
    is_active: bool
    is_trusted: bool
    contact_email: Optional[str] = None
    website_url: Optional[str] = None
    access_token_lifetime: int
    refresh_token_lifetime: Optional[int] = None
    rate_limit_per_minute: int
    rate_limit_per_hour: int
    allowed_ips: Optional[str] = None
    webhook_url: Optional[str] = None
    last_used: Optional[datetime] = None
    total_requests: int
    created_at: datetime
    updated_at: datetime
    scopes: List[ScopeInfo] = []
    can_authenticate: bool
    supports_refresh_tokens: bool

    class Config:
        from_attributes = True


class ServiceClientCreateResponse(BaseModel):
    """Schema for service client creation response."""
    client: ServiceClientResponse
    client_secret: str = Field(..., description="Client secret (only shown once)")


class ServiceClientListResponse(BaseModel):
    """Schema for paginated service client list response."""
    clients: List[ServiceClientResponse]
    total: int
    page: int
    per_page: int
    pages: int


class ServiceClientSearchParams(BaseModel):
    """Schema for service client search parameters."""
    search: Optional[str] = Field(None, description="Search term for name or client_id")
    is_active: Optional[bool] = Field(None, description="Filter by active status")
    is_trusted: Optional[bool] = Field(None, description="Filter by trusted status")
    client_type: Optional[str] = Field(None, description="Filter by client type")
    scope_id: Optional[str] = Field(None, description="Filter by scope ID")
    page: int = Field(1, ge=1, description="Page number")
    per_page: int = Field(20, ge=1, le=100, description="Items per page")


class ServiceClientScopeUpdate(BaseModel):
    """Schema for updating service client scopes."""
    scope_ids: List[str] = Field(..., description="List of scope IDs to assign")


class ServiceClientStats(BaseModel):
    """Schema for service client statistics."""
    total_clients: int
    active_clients: int
    trusted_clients: int
    total_requests_today: int
    most_active_clients: List[dict]  # [{"client_id": "api-gateway", "requests": 1500}, ...]


class ServiceClientUsage(BaseModel):
    """Schema for service client usage information."""
    client_id: str
    client_name: str
    requests_today: int
    requests_this_week: int
    requests_this_month: int
    last_used: Optional[datetime] = None
    average_requests_per_day: float
    rate_limit_hits: int

    class Config:
        from_attributes = True


class ServiceClientUsageResponse(BaseModel):
    """Schema for service client usage response."""
    usage: List[ServiceClientUsage]
    total_requests: int
    period_start: datetime
    period_end: datetime


class ServiceClientAccessLog(BaseModel):
    """Schema for service client access log entry."""
    id: str
    client_id: str
    endpoint: str
    method: str
    status_code: int
    response_time_ms: int
    ip_address: str
    user_agent: Optional[str] = None
    timestamp: datetime
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class ServiceClientAccessLogResponse(BaseModel):
    """Schema for service client access log response."""
    logs: List[ServiceClientAccessLog]
    total: int
    page: int
    per_page: int


class ServiceClientRateLimit(BaseModel):
    """Schema for service client rate limit information."""
    client_id: str
    per_minute_limit: int
    per_minute_remaining: int
    per_minute_reset: datetime
    per_hour_limit: int
    per_hour_remaining: int
    per_hour_reset: datetime
    is_rate_limited: bool


class ServiceClientHealthCheck(BaseModel):
    """Schema for service client health check."""
    client_id: str
    is_healthy: bool
    last_successful_request: Optional[datetime] = None
    consecutive_failures: int
    webhook_status: Optional[str] = Field(None, description="Webhook endpoint status")
    response_time_avg_ms: Optional[float] = None


class ServiceClientHealthResponse(BaseModel):
    """Schema for service client health response."""
    health_checks: List[ServiceClientHealthCheck]
    healthy_count: int
    unhealthy_count: int
    total_count: int


class ServiceClientWebhookTest(BaseModel):
    """Schema for service client webhook test."""
    test_payload: dict = Field(default={}, description="Test payload to send")
    timeout_seconds: int = Field(30, ge=5, le=120, description="Request timeout")


class ServiceClientWebhookTestResponse(BaseModel):
    """Schema for service client webhook test response."""
    success: bool
    status_code: Optional[int] = None
    response_body: Optional[str] = None
    response_time_ms: int
    error_message: Optional[str] = None


class ServiceClientPermissions(BaseModel):
    """Schema for service client permissions."""
    client_id: str
    scopes: List[str] = Field(default=[], description="Client's scopes")
    resources: dict = Field(default={}, description="Permissions organized by resource")
    can_access_admin: bool = Field(False, description="Whether client has admin access")


class ServiceClientToken(BaseModel):
    """Schema for service client token information."""
    client_id: str
    token_type: str
    scopes: List[str] = []
    expires_at: datetime
    issued_at: datetime
    is_active: bool

    class Config:
        from_attributes = True


class ServiceClientTokensResponse(BaseModel):
    """Schema for service client active tokens response."""
    tokens: List[ServiceClientToken]
    total_active: int
    total_expired: int


class ServiceClientAuditLog(BaseModel):
    """Schema for service client audit log entry."""
    id: str
    client_id: str
    action: str = Field(..., description="Action performed (created, updated, deleted, etc.)")
    changes: Optional[dict] = Field(None, description="Changes made")
    performed_by: str = Field(..., description="User ID who performed the action")
    ip_address: str
    timestamp: datetime
    reason: Optional[str] = Field(None, description="Reason for the change")

    class Config:
        from_attributes = True


class ServiceClientAuditResponse(BaseModel):
    """Schema for service client audit log response."""
    audit_logs: List[ServiceClientAuditLog]
    total: int
    page: int
    per_page: int