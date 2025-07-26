"""Unit tests for database models."""

import pytest
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.role import Role
from app.models.scope import Scope
from app.models.service_client import ServiceClient
from app.models.refresh_token import RefreshToken
from app.core.password import hash_password


class TestUserModel:
    """Test User model functionality."""

    @pytest.mark.unit
    async def test_user_creation(self, db_session: AsyncSession):
        """Test user creation."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash=hash_password("TestPassword123!"),
            first_name="Test",
            last_name="User",
        )
        
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        
        assert user.id is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_active is True  # Default value
        assert user.created_at is not None

    @pytest.mark.unit
    def test_user_full_name_property(self):
        """Test user full name property."""
        # Both names provided
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
            first_name="John",
            last_name="Doe",
        )
        assert user.full_name == "John Doe"
        
        # Only first name
        user.last_name = None
        assert user.full_name == "test"  # Falls back to username when only first name is None
        
        # Only last name
        user.first_name = None
        user.last_name = "Doe"
        assert user.full_name == "test"  # Falls back to username when only last name is set
        
        # No names, fallback to display name
        user.first_name = None
        user.last_name = None
        user.display_name = "TestDisplay"
        assert user.full_name == "TestDisplay"
        
        # No names, fallback to username
        user.display_name = None
        assert user.full_name == "test"

    @pytest.mark.unit
    def test_user_can_login_property(self):
        """Test user can_login property."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
            is_active=True,
        )
        
        # Active user should be able to login
        assert user.can_login is True
        
        # Inactive user should not be able to login
        user.is_active = False
        assert user.can_login is False
        
        # Locked user should not be able to login
        user.is_active = True
        user.locked_until = datetime.utcnow() + timedelta(hours=1)
        assert user.can_login is False
        
        # Previously locked user should be able to login
        user.locked_until = datetime.utcnow() - timedelta(hours=1)
        assert user.can_login is True

    @pytest.mark.unit
    def test_user_is_locked_property(self):
        """Test user is_locked property."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
        )
        
        # User without lock should not be locked
        assert user.is_locked is False
        
        # User locked in future should be locked
        user.locked_until = datetime.utcnow() + timedelta(hours=1)
        assert user.is_locked is True
        
        # User locked in past should not be locked
        user.locked_until = datetime.utcnow() - timedelta(hours=1)
        assert user.is_locked is False

    @pytest.mark.unit
    async def test_user_scope_methods(self, db_session: AsyncSession):
        """Test user scope management methods."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
        )
        
        role = Role(name="test_role", description="Test role")
        scope1 = Scope(name="read:test", description="Read test")
        scope2 = Scope(name="write:test", description="Write test")
        
        role.scopes.append(scope1)
        user.roles.append(role)
        
        db_session.add_all([user, role, scope1, scope2])
        await db_session.commit()
        await db_session.refresh(user)
        
        # Test get_scopes
        scopes = await user.get_scopes()
        assert "read:test" in scopes
        assert "write:test" not in scopes
        
        # Test has_scope
        assert await user.has_scope("read:test") is True
        assert await user.has_scope("write:test") is False

    @pytest.mark.unit
    async def test_user_role_methods(self, db_session: AsyncSession):
        """Test user role management methods."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
        )
        
        role1 = Role(name="role1", description="Role 1")
        role2 = Role(name="role2", description="Role 2")
        
        db_session.add_all([user, role1, role2])
        await db_session.commit()
        
        # Test has_role
        await db_session.refresh(user)
        assert await user.has_role("role1") is False
        
        # Add role
        user.roles.append(role1)
        await db_session.commit()
        await db_session.refresh(user)
        
        assert await user.has_role("role1") is True
        assert await user.has_role("role2") is False

    @pytest.mark.unit
    async def test_user_admin_methods(self):
        """Test user admin-related methods."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
        )
        
        # Test superuser
        user.is_superuser = True
        assert await user.is_admin() is True
        
        # Test admin role
        user.is_superuser = False
        admin_role = Role(name="admin", description="Admin")
        user.roles.append(admin_role)
        assert await user.is_admin() is True

    @pytest.mark.unit
    async def test_user_resource_access(self):
        """Test user resource access methods."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
        )
        
        # Superuser can access everything
        user.is_superuser = True
        assert await user.can_access_resource("profile", "read") is True
        assert await user.can_access_resource("admin", "write") is True
        
        # Regular user with specific scope
        user.is_superuser = False
        role = Role(name="user", description="User")
        scope = Scope(name="read:profile", description="Read profile")
        role.scopes.append(scope)
        user.roles.append(role)
        
        assert await user.can_access_resource("profile", "read") is True
        assert await user.can_access_resource("profile", "write") is False

    @pytest.mark.unit
    def test_user_failed_login_methods(self):
        """Test user failed login methods."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
        )
        
        # Test failed login attempts
        assert user.failed_login_attempts == 0
        
        user.increment_failed_login()
        assert user.failed_login_attempts == 1
        
        user.reset_failed_logins()
        assert user.failed_login_attempts == 0

    @pytest.mark.unit
    def test_user_update_last_login(self):
        """Test updating last login timestamp."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
        )
        
        assert user.last_login is None
        
        user.update_last_login()
        assert user.last_login is not None
        assert isinstance(user.last_login, datetime)
        assert user.failed_login_attempts == 0

    @pytest.mark.unit
    def test_user_to_dict(self):
        """Test user to_dict method."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="secret_hash",
            first_name="Test",
            last_name="User",
        )
        
        # Test without sensitive info
        user_dict = user.to_dict(include_sensitive=False)
        assert "password_hash" not in user_dict
        assert user_dict["username"] == "test"
        assert user_dict["full_name"] == "Test User"
        assert user_dict["can_login"] is True
        
        # Test with sensitive info
        user_dict = user.to_dict(include_sensitive=True)
        assert user_dict["password_hash"] == "secret_hash"


class TestRoleModel:
    """Test Role model functionality."""

    @pytest.mark.unit
    async def test_role_creation(self, db_session: AsyncSession):
        """Test role creation."""
        role = Role(
            name="test_role",
            description="Test role for testing",
        )
        
        db_session.add(role)
        await db_session.commit()
        await db_session.refresh(role)
        
        assert role.id is not None
        assert role.name == "test_role"
        assert role.description == "Test role for testing"
        assert role.created_at is not None

    @pytest.mark.unit
    async def test_role_scope_methods(self, db_session: AsyncSession):
        """Test role scope management methods."""
        role = Role(name="test_role", description="Test role")
        scope1 = Scope(name="read:test", description="Read test")
        scope2 = Scope(name="write:test", description="Write test")
        
        db_session.add_all([role, scope1, scope2])
        await db_session.commit()
        
        # Test has_scope
        await db_session.refresh(role)
        assert await role.has_scope("read:test") is False
        
        # Add scope
        role.scopes.append(scope1)
        await db_session.commit()
        await db_session.refresh(role)
        
        assert await role.has_scope("read:test") is True
        assert await role.has_scope("write:test") is False
        
        # Test get_scope_names
        scope_names = role.get_scope_names()
        assert "read:test" in scope_names
        assert "write:test" not in scope_names

    @pytest.mark.unit
    def test_role_default_roles(self):
        """Test default roles list."""
        default_roles = Role.get_default_roles()
        
        assert isinstance(default_roles, list)
        assert len(default_roles) > 0
        
        # Check structure of default roles - they are just strings
        for role_name in default_roles:
            assert isinstance(role_name, str)
            assert len(role_name) > 0

    @pytest.mark.unit
    def test_role_to_dict(self):
        """Test role to_dict method."""
        role = Role(name="test_role", description="Test role")
        
        role_dict = role.to_dict()
        assert role_dict["name"] == "test_role"
        assert role_dict["description"] == "Test role"
        assert "scope_names" in role_dict
        assert "user_count" in role_dict


class TestScopeModel:
    """Test Scope model functionality."""

    @pytest.mark.unit
    async def test_scope_creation(self, db_session: AsyncSession):
        """Test scope creation."""
        scope = Scope(
            name="read:profile",
            description="Read user profile",
            resource="profile",
        )
        
        db_session.add(scope)
        await db_session.commit()
        await db_session.refresh(scope)
        
        assert scope.id is not None
        assert scope.name == "read:profile"
        assert scope.description == "Read user profile"
        assert scope.resource == "profile"

    @pytest.mark.unit
    def test_scope_properties(self):
        """Test scope properties."""
        scope = Scope(name="write:profile", resource="profile")
        
        assert scope.action == "write"
        assert scope.resource_name == "profile"
        
        # Test scope without colon
        scope.name = "admin"
        assert scope.action == "admin"
        assert scope.resource_name == "profile"  # Fixed: scope has resource set to "profile"

    @pytest.mark.unit
    def test_scope_type_checks(self):
        """Test scope type checking methods."""
        read_scope = Scope(name="read:profile")
        write_scope = Scope(name="write:profile")
        admin_scope = Scope(name="admin:users")
        
        # Test read scope
        assert read_scope.is_read_scope() is True
        assert read_scope.is_write_scope() is False
        assert read_scope.is_admin_scope() is False
        
        # Test write scope
        assert write_scope.is_read_scope() is False
        assert write_scope.is_write_scope() is True
        assert write_scope.is_admin_scope() is False
        
        # Test admin scope
        assert admin_scope.is_read_scope() is False
        assert admin_scope.is_write_scope() is False
        assert admin_scope.is_admin_scope() is True

    @pytest.mark.unit
    def test_scope_default_scopes(self):
        """Test default scopes list."""
        default_scopes = Scope.get_default_scopes()
        
        assert isinstance(default_scopes, list)
        assert len(default_scopes) > 0
        
        # Check structure of default scopes
        for scope_data in default_scopes:
            assert "name" in scope_data
            assert "description" in scope_data
            assert "resource" in scope_data

    @pytest.mark.unit
    def test_scope_parse_scope_string(self):
        """Test parsing scope string."""
        scope_string = "read:profile write:profile admin:users"
        scopes = Scope.parse_scope_string(scope_string)
        
        assert scopes == ["read:profile", "write:profile", "admin:users"]
        
        # Test empty string
        assert Scope.parse_scope_string("") == []
        assert Scope.parse_scope_string(None) == []

    @pytest.mark.unit
    def test_scope_validate_format(self):
        """Test scope format validation."""
        # Valid scopes
        assert Scope.validate_scope_format("read:profile") is True
        assert Scope.validate_scope_format("admin_users") is True
        assert Scope.validate_scope_format("service-api") is True
        
        # Invalid scopes
        assert Scope.validate_scope_format("") is False
        assert Scope.validate_scope_format(None) is False
        assert Scope.validate_scope_format("invalid scope") is False
        assert Scope.validate_scope_format("invalid@scope") is False


class TestServiceClientModel:
    """Test ServiceClient model functionality."""

    @pytest.mark.unit
    async def test_service_client_creation(self, db_session: AsyncSession):
        """Test service client creation."""
        client = ServiceClient(
            client_id="test-service",
            client_secret_hash=hash_password("secret"),
            name="Test Service",
            description="Test service client",
        )
        
        db_session.add(client)
        await db_session.commit()
        await db_session.refresh(client)
        
        assert client.id is not None
        assert client.client_id == "test-service"
        assert client.name == "Test Service"
        assert client.is_active is True

    @pytest.mark.unit
    def test_service_client_properties(self):
        """Test service client properties."""
        client = ServiceClient(
            client_id="test",
            client_secret_hash="hash",
            name="Test",
            is_active=True,
        )
        
        assert client.can_authenticate is True
        
        client.is_active = False
        assert client.can_authenticate is False

    @pytest.mark.unit
    def test_service_client_scope_methods(self):
        """Test service client scope methods."""
        client = ServiceClient(
            client_id="test",
            client_secret_hash="hash",
            name="Test",
        )
        
        scope = Scope(name="read:test", description="Read test")
        client.scopes.append(scope)
        
        assert client.has_scope("read:test") is True
        assert client.has_scope("write:test") is False
        
        scope_names = client.get_scope_names()
        assert "read:test" in scope_names

    @pytest.mark.unit
    def test_service_client_resource_access(self):
        """Test service client resource access."""
        client = ServiceClient(
            client_id="test",
            client_secret_hash="hash",
            name="Test",
            is_trusted=True,
        )
        
        # Trusted client with admin scope
        admin_scope = Scope(name="admin:system", description="System admin")
        client.scopes.append(admin_scope)
        
        assert client.can_access_resource("profile", "read") is True
        assert client.can_access_resource("admin", "write") is True

    @pytest.mark.unit
    def test_service_client_ip_validation(self):
        """Test IP address validation."""
        client = ServiceClient(
            client_id="test",
            client_secret_hash="hash",
            name="Test",
            allowed_ips="192.168.1.1,10.0.0.*",
        )
        
        assert client.is_ip_allowed("192.168.1.1") is True
        assert client.is_ip_allowed("10.0.0.5") is True
        assert client.is_ip_allowed("192.168.1.2") is False
        
        # Client without IP restrictions
        client.allowed_ips = None
        assert client.is_ip_allowed("any-ip") is True

    @pytest.mark.unit
    def test_service_client_usage_tracking(self):
        """Test usage tracking."""
        client = ServiceClient(
            client_id="test",
            client_secret_hash="hash",
            name="Test",
        )
        
        assert client.last_used is None
        assert client.total_requests == 0
        
        client.update_usage()
        assert client.last_used is not None
        assert client.total_requests == 1

    @pytest.mark.unit
    def test_service_client_default_clients(self):
        """Test default service clients."""
        default_clients = ServiceClient.create_default_clients()
        
        assert isinstance(default_clients, list)
        assert len(default_clients) > 0
        
        for client_data in default_clients:
            assert "client_id" in client_data
            assert "name" in client_data
            assert "description" in client_data


class TestRefreshTokenModel:
    """Test RefreshToken model functionality."""

    @pytest.mark.unit
    async def test_refresh_token_creation(self, db_session: AsyncSession):
        """Test refresh token creation."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
        )
        
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        
        token = RefreshToken.create_token(
            user_id=user.id,
            token_hash="hashed_token",
            expires_in_seconds=3600,
            client_ip="192.168.1.1",
        )
        
        db_session.add(token)
        await db_session.commit()
        await db_session.refresh(token)
        
        assert token.id is not None
        assert token.user_id == user.id
        assert token.token_hash == "hashed_token"
        assert token.client_ip == "192.168.1.1"
        assert token.token_id is not None

    @pytest.mark.unit
    def test_refresh_token_properties(self):
        """Test refresh token properties."""
        from datetime import timezone
        token = RefreshToken(
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            is_revoked=False,
            is_used=False,
        )
        
        assert token.is_expired is False
        assert token.is_valid is True
        
        # Test expired token
        token.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        assert token.is_expired is True
        assert token.is_valid is False
        
        # Test revoked token
        token.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        token.is_revoked = True
        assert token.is_valid is False
        
        # Test used token
        token.is_revoked = False
        token.is_used = True
        assert token.is_valid is False

    @pytest.mark.unit
    def test_refresh_token_revocation(self):
        """Test token revocation."""
        from datetime import timezone
        token = RefreshToken(
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            is_revoked=False,
        )
        
        assert token.is_revoked is False
        assert token.revoked_at is None
        
        token.revoke("security")
        
        assert token.is_revoked is True
        assert token.revoked_at is not None
        assert token.revocation_reason == "security"

    @pytest.mark.unit
    def test_refresh_token_usage(self):
        """Test token usage tracking."""
        token = RefreshToken()
        
        assert token.last_used_at is None
        assert token.use_count == 0
        
        token.mark_as_used()
        
        assert token.last_used_at is not None
        assert token.use_count == 1
        assert token.is_used is True

    @pytest.mark.unit
    def test_refresh_token_expiry_extension(self):
        """Test extending token expiry."""
        from datetime import timezone
        original_expiry = datetime.now(timezone.utc) + timedelta(days=1)
        token = RefreshToken(expires_at=original_expiry)
        
        token.extend_expiry(3600)  # 1 hour
        
        assert token.expires_at > original_expiry
        # Should be approximately 1 hour from original expiry
        expected_expiry = original_expiry + timedelta(seconds=3600)
        time_diff = abs((token.expires_at - expected_expiry).total_seconds())
        assert time_diff < 60  # Within 1 minute

    @pytest.mark.unit
    def test_refresh_token_remaining_lifetime(self):
        """Test remaining lifetime calculation."""
        from datetime import timezone
        # Token expiring in 1 hour
        token = RefreshToken(
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        remaining = token.get_remaining_lifetime()
        assert 3500 < remaining < 3700  # Approximately 1 hour
        
        # Expired token
        token.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        assert token.get_remaining_lifetime() == 0

    @pytest.mark.unit
    def test_refresh_token_near_expiry(self):
        """Test near expiry detection."""
        from datetime import timezone
        # Token expiring in 30 minutes
        token = RefreshToken(
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30)
        )
        
        assert token.is_near_expiry(60) is True  # Within 60 minutes
        assert token.is_near_expiry(15) is False  # Not within 15 minutes
        
        # Expired token
        token.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        assert token.is_near_expiry() is True