"""Tests for User model."""

import pytest
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.role import Role
from app.models.scope import Scope
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
        await db_session.refresh(user)
        
        # Test has_role
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

    @pytest.mark.unit
    async def test_user_class_methods(self, db_session: AsyncSession):
        """Test User class methods."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash",
        )
        
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        
        # Test get_by_username
        found_user = await User.get_by_username(db_session, "testuser")
        assert found_user is not None
        assert found_user.username == "testuser"
        
        # Test get_by_email
        found_user = await User.get_by_email(db_session, "test@example.com")
        assert found_user is not None
        assert found_user.email == "test@example.com"
        
        # Test get_by_username_or_email
        found_user = await User.get_by_username_or_email(db_session, "testuser")
        assert found_user is not None
        
        found_user = await User.get_by_username_or_email(db_session, "test@example.com")
        assert found_user is not None
        
        # Test not found
        found_user = await User.get_by_username(db_session, "nonexistent")
        assert found_user is None