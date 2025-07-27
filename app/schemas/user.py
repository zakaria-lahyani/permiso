"""User-related Pydantic schemas for API request/response models."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field, field_validator
import re
import uuid


class UserBase(BaseModel):
    """Base user schema with common fields."""
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: EmailStr = Field(..., description="User's email address")
    first_name: Optional[str] = Field(None, max_length=100, description="User's first name")
    last_name: Optional[str] = Field(None, max_length=100, description="User's last name")
    display_name: Optional[str] = Field(None, max_length=100, description="Display name for UI")
    bio: Optional[str] = Field(None, max_length=1000, description="User biography")
    is_active: bool = Field(True, description="Whether the user account is active")
    is_verified: bool = Field(False, description="Whether the user's email is verified")

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        """Validate username format."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v.lower()


class UserCreate(UserBase):
    """Schema for creating a new user."""
    password: str = Field(..., min_length=8, max_length=128, description="User's password")
    role_ids: Optional[List[str]] = Field(default=[], description="List of role IDs to assign")

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class UserUpdate(BaseModel):
    """Schema for updating an existing user."""
    email: Optional[EmailStr] = Field(None, description="User's email address")
    first_name: Optional[str] = Field(None, max_length=100, description="User's first name")
    last_name: Optional[str] = Field(None, max_length=100, description="User's last name")
    display_name: Optional[str] = Field(None, max_length=100, description="Display name for UI")
    bio: Optional[str] = Field(None, max_length=1000, description="User biography")
    is_active: Optional[bool] = Field(None, description="Whether the user account is active")
    is_verified: Optional[bool] = Field(None, description="Whether the user's email is verified")
    role_ids: Optional[List[str]] = Field(None, description="List of role IDs to assign")


class UserPasswordUpdate(BaseModel):
    """Schema for updating user password."""
    current_password: str = Field(..., description="Current password for verification")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")

    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        """Validate new password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class RoleInfo(BaseModel):
    """Role information for user responses."""
    id: str = Field(..., description="Role ID")
    name: str
    description: Optional[str] = None

    model_config = {
        "from_attributes": True
    }


class UserResponse(BaseModel):
    """Schema for user response."""
    id: str = Field(..., description="User ID")
    username: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None
    is_active: bool
    is_verified: bool
    is_superuser: bool
    full_name: str
    last_login: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    roles: List[RoleInfo] = []
    scope_names: List[str] = []
    scopes: List[str] = []  # Add scopes field that tests expect

    model_config = {
        "from_attributes": True,
        "json_encoders": {
            datetime: lambda v: v.isoformat(),
        }
    }

    @classmethod
    def from_orm(cls, user):
        """Create UserResponse from User ORM object."""
        try:
            # Get scope names synchronously from the user's to_dict method
            user_dict = user.to_dict()
            
            # Convert roles to RoleInfo objects
            roles = []
            if hasattr(user, 'roles') and user.roles:
                for role in user.roles:
                    try:
                        roles.append(RoleInfo(
                            id=str(role.id),  # Convert UUID to string explicitly
                            name=role.name,
                            description=getattr(role, 'description', None)
                        ))
                    except Exception as e:
                        print(f"Error processing role {role}: {e}")
                        continue
            
            # Get scope names - use both scope_names and scopes for compatibility
            scope_names = user_dict.get('scope_names', [])
            scopes = user_dict.get('scopes', scope_names)  # Use scopes if available, fallback to scope_names
            
            return cls(
                id=str(user.id),  # Convert UUID to string explicitly
                username=user.username,
                email=user.email,
                first_name=user.first_name,
                last_name=user.last_name,
                display_name=user.display_name,
                bio=user.bio,
                is_active=user.is_active,
                is_verified=user.is_verified,
                is_superuser=user.is_superuser,
                full_name=user.full_name,
                last_login=user.last_login,
                created_at=user.created_at,
                updated_at=user.updated_at,
                roles=roles,
                scope_names=scope_names,
                scopes=scopes
            )
        except Exception as e:
            print(f"Error in UserResponse.from_orm: {e}")
            print(f"User object: {user}")
            raise


class UserListResponse(BaseModel):
    """Schema for paginated user list response."""
    users: List[UserResponse]
    total: int
    page: int
    per_page: int
    pages: int


class UserSearchParams(BaseModel):
    """Schema for user search parameters."""
    search: Optional[str] = Field(None, description="Search term for username, email, or name")
    is_active: Optional[bool] = Field(None, description="Filter by active status")
    is_verified: Optional[bool] = Field(None, description="Filter by verification status")
    role_id: Optional[str] = Field(None, description="Filter by role ID")
    page: int = Field(1, ge=1, description="Page number")
    per_page: int = Field(20, ge=1, le=100, description="Items per page")


class UserRoleUpdate(BaseModel):
    """Schema for updating user roles."""
    role_ids: List[str] = Field(..., description="List of role IDs to assign")


class UserProfileUpdate(BaseModel):
    """Schema for user profile self-update."""
    email: Optional[EmailStr] = Field(None, description="User's email address")
    first_name: Optional[str] = Field(None, max_length=100, description="User's first name")
    last_name: Optional[str] = Field(None, max_length=100, description="User's last name")
    display_name: Optional[str] = Field(None, max_length=100, description="Display name for UI")
    bio: Optional[str] = Field(None, max_length=1000, description="User biography")


class UserStats(BaseModel):
    """Schema for user statistics."""
    total_users: int
    active_users: int
    verified_users: int
    locked_users: int
    recent_registrations: int  # Last 30 days


class PasswordResetRequest(BaseModel):
    """Schema for password reset request."""
    email: EmailStr = Field(..., description="Email address for password reset")


class PasswordResetConfirm(BaseModel):
    """Schema for password reset confirmation."""
    token: str = Field(..., description="Password reset token")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")

    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        """Validate new password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class EmailVerificationRequest(BaseModel):
    """Schema for email verification request."""
    email: EmailStr = Field(..., description="Email address to verify")


class EmailVerificationConfirm(BaseModel):
    """Schema for email verification confirmation."""
    token: str = Field(..., description="Email verification token")


class UserActivityLog(BaseModel):
    """Schema for user activity log entry."""
    id: str
    user_id: str
    action: str
    details: Optional[dict] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime

    model_config = {
        "from_attributes": True
    }


class UserActivityResponse(BaseModel):
    """Schema for user activity response."""
    activities: List[UserActivityLog]
    total: int
    page: int
    per_page: int