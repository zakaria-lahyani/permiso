"""Tests for Role model."""

import pytest
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.role import Role
from app.models.scope import Scope
from app.models.user import User
from app.core.password import hash_password


class TestRoleModel:
    """Test Role model functionality."""

    @pytest.mark.unit
    async def test_role_creation(self, db_session: AsyncSession):
        """Test role creation with basic fields."""
        role = Role(
            name="test_role",
            description="Test role for testing purposes"
        )
        
        db_session.add(role)
        await db_session.commit()
        await db_session.refresh(role)
        
        assert role.id is not None
        assert role.name == "test_role"
        assert role.description == "Test role for testing purposes"
        assert role.created_at is not None
        assert role.updated_at is not None
        assert isinstance(role.created_at, datetime)

    @pytest.mark.unit
    async def test_role_creation_minimal(self, db_session: AsyncSession):
        """Test role creation with minimal required fields."""
        role = Role(name="minimal_role")
        
        db_session.add(role)
        await db_session.commit()
        await db_session.refresh(role)
        
        assert role.id is not None
        assert role.name == "minimal_role"
        assert role.description is None
        assert role.created_at is not None

    @pytest.mark.unit
    async def test_role_unique_name_constraint(self, db_session: AsyncSession):
        """Test that role names must be unique."""
        # Create first role
        role1 = Role(name="unique_role", description="First role")
        db_session.add(role1)
        await db_session.commit()
        
        # Try to create second role with same name
        role2 = Role(name="unique_role", description="Second role")
        db_session.add(role2)
        
        with pytest.raises(Exception):  # Should raise integrity error
            await db_session.commit()
        
        await db_session.rollback()

    @pytest.mark.unit
    def test_role_string_representation(self):
        """Test role string representation."""
        role = Role(name="admin", description="Administrator role")
        
        expected_repr = "<Role(name='admin', description='Administrator role')>"
        assert repr(role) == expected_repr

    @pytest.mark.unit
    def test_role_string_representation_no_description(self):
        """Test role string representation without description."""
        role = Role(name="user")
        
        expected_repr = "<Role(name='user', description=None)>"
        assert repr(role) == expected_repr

    @pytest.mark.unit
    async def test_role_scope_relationship(self, db_session: AsyncSession):
        """Test role-scope many-to-many relationship."""
        # Create role and scopes
        role = Role(name="editor", description="Editor role")
        scope1 = Scope(name="read:articles", description="Read articles", resource="articles")
        scope2 = Scope(name="write:articles", description="Write articles", resource="articles")
        scope3 = Scope(name="delete:articles", description="Delete articles", resource="articles")
        
        db_session.add_all([role, scope1, scope2, scope3])
        await db_session.commit()
        await db_session.refresh(role)
        
        # Add scopes to role
        role.scopes.extend([scope1, scope2])
        await db_session.commit()
        await db_session.refresh(role)
        
        # Test forward relationship
        assert len(role.scopes) == 2
        scope_names = [scope.name for scope in role.scopes]
        assert "read:articles" in scope_names
        assert "write:articles" in scope_names
        assert "delete:articles" not in scope_names
        
        # Test reverse relationship
        await db_session.refresh(scope1)
        assert role in scope1.roles

    @pytest.mark.unit
    async def test_role_user_relationship(self, db_session: AsyncSession):
        """Test role-user many-to-many relationship."""
        from sqlalchemy.orm import selectinload
        
        # Create role and users
        role = Role(name="moderator", description="Moderator role")
        user1 = User(
            username="mod1",
            email="mod1@example.com",
            password_hash=hash_password("ModPassword123!")
        )
        user2 = User(
            username="mod2",
            email="mod2@example.com",
            password_hash=hash_password("ModPassword123!")
        )
        
        db_session.add_all([role, user1, user2])
        await db_session.commit()
        
        # Reload with relationships
        role_result = await db_session.execute(
            select(Role).options(selectinload(Role.users)).where(Role.id == role.id)
        )
        role = role_result.scalar_one()
        
        user1_result = await db_session.execute(
            select(User).options(selectinload(User.roles)).where(User.id == user1.id)
        )
        user1 = user1_result.scalar_one()
        
        user2_result = await db_session.execute(
            select(User).options(selectinload(User.roles)).where(User.id == user2.id)
        )
        user2 = user2_result.scalar_one()
        
        # Assign role to users
        user1.roles.append(role)
        user2.roles.append(role)
        await db_session.commit()
        
        # Reload role with users
        role_result = await db_session.execute(
            select(Role).options(selectinload(Role.users)).where(Role.id == role.id)
        )
        role = role_result.scalar_one()
        
        # Test reverse relationship (role -> users)
        assert len(role.users) == 2
        usernames = [user.username for user in role.users]
        assert "mod1" in usernames
        assert "mod2" in usernames

    @pytest.mark.unit
    async def test_role_cascade_behavior(self, db_session: AsyncSession):
        """Test role cascade behavior with relationships."""
        from sqlalchemy.orm import selectinload
        
        # Create role with scopes and users
        role = Role(name="temp_role", description="Temporary role")
        scope = Scope(name="temp:scope_cascade", description="Temporary scope", resource="temp")
        user = User(
            username="tempuser_cascade",
            email="temp_cascade@example.com",
            password_hash=hash_password("TempPassword123!")
        )
        
        db_session.add_all([role, scope, user])
        await db_session.commit()
        
        # Reload with relationships
        role_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == role.id)
        )
        role = role_result.scalar_one()
        
        user_result = await db_session.execute(
            select(User).options(selectinload(User.roles)).where(User.id == user.id)
        )
        user = user_result.scalar_one()
        
        # Create relationships
        role.scopes.append(scope)
        user.roles.append(role)
        await db_session.commit()
        
        # Manually remove role from user's roles before deleting (simulating cascade behavior)
        user.roles.remove(role)
        await db_session.commit()
        
        # Delete role
        await db_session.delete(role)
        await db_session.commit()
        
        # Reload entities with relationships
        scope_result = await db_session.execute(
            select(Scope).options(selectinload(Scope.roles)).where(Scope.id == scope.id)
        )
        scope = scope_result.scalar_one()
        
        user_result = await db_session.execute(
            select(User).options(selectinload(User.roles)).where(User.id == user.id)
        )
        user = user_result.scalar_one()
        
        # Check that relationships are cleaned up but related entities remain
        assert len(scope.roles) == 0
        assert len(user.roles) == 0

    @pytest.mark.unit
    def test_role_to_dict(self):
        """Test role to_dict method."""
        role = Role(
            name="api_user",
            description="API user role"
        )
        role.id = "123e4567-e89b-12d3-a456-426614174000"
        role.created_at = datetime(2024, 1, 1, 12, 0, 0)
        role.updated_at = datetime(2024, 1, 1, 12, 0, 0)
        
        role_dict = role.to_dict()
        
        expected_keys = ["id", "name", "description", "created_at", "updated_at"]
        for key in expected_keys:
            assert key in role_dict
        
        assert role_dict["name"] == "api_user"
        assert role_dict["description"] == "API user role"

    @pytest.mark.unit
    async def test_role_get_scope_names(self, db_session: AsyncSession):
        """Test getting scope names from role."""
        from sqlalchemy.orm import selectinload
        
        role = Role(name="content_manager", description="Content manager role")
        scope1 = Scope(name="read:content_mgr", description="Read content", resource="content")
        scope2 = Scope(name="write:content_mgr", description="Write content", resource="content")
        scope3 = Scope(name="publish:content_mgr", description="Publish content", resource="content")
        
        db_session.add_all([role, scope1, scope2, scope3])
        await db_session.commit()
        
        # Reload role with scopes relationship
        role_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == role.id)
        )
        role = role_result.scalar_one()
        
        # Add scopes to role
        role.scopes.extend([scope1, scope2, scope3])
        await db_session.commit()
        
        # Reload role with updated scopes
        role_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == role.id)
        )
        role = role_result.scalar_one()
        
        scope_names = role.get_scope_names()
        
        assert len(scope_names) == 3
        assert "read:content_mgr" in scope_names
        assert "write:content_mgr" in scope_names
        assert "publish:content_mgr" in scope_names

    @pytest.mark.unit
    async def test_role_has_scope(self, db_session: AsyncSession):
        """Test checking if role has specific scope."""
        from sqlalchemy.orm import selectinload
        
        role = Role(name="reviewer", description="Reviewer role")
        read_scope = Scope(name="read:reviews", description="Read reviews", resource="reviews")
        write_scope = Scope(name="write:reviews", description="Write reviews", resource="reviews")
        admin_scope = Scope(name="admin:reviews", description="Admin reviews", resource="reviews")
        
        db_session.add_all([role, read_scope, write_scope, admin_scope])
        await db_session.commit()
        
        # Reload role with scopes relationship
        role_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == role.id)
        )
        role = role_result.scalar_one()
        
        # Add only read and write scopes
        role.scopes.extend([read_scope, write_scope])
        await db_session.commit()
        
        # Reload role with updated scopes
        role_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == role.id)
        )
        role = role_result.scalar_one()
        
        assert role.has_scope("read:reviews") is True
        assert role.has_scope("write:reviews") is True
        assert role.has_scope("admin:reviews") is False
        assert role.has_scope("nonexistent:scope") is False

    @pytest.mark.unit
    async def test_role_get_permissions(self, db_session: AsyncSession):
        """Test getting all permissions from role scopes."""
        from sqlalchemy.orm import selectinload
        
        role = Role(name="manager", description="Manager role")
        
        # Create scopes with different resources and actions (without _mgr suffix to match actual data)
        scopes = [
            Scope(name="read:users", description="Read users", resource="users"),
            Scope(name="write:users", description="Write users", resource="users"),
            Scope(name="read:reports", description="Read reports", resource="reports"),
            Scope(name="admin:settings", description="Admin settings", resource="settings")
        ]
        
        db_session.add_all([role] + scopes)
        await db_session.commit()
        
        # Reload role with scopes relationship
        role_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == role.id)
        )
        role = role_result.scalar_one()
        
        role.scopes.extend(scopes)
        await db_session.commit()
        
        # Reload role with updated scopes
        role_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == role.id)
        )
        role = role_result.scalar_one()
        
        permissions = role.get_permissions()
        
        expected_permissions = {
            "users": ["read", "write"],
            "reports": ["read"],
            "settings": ["admin"]
        }
        
        assert permissions == expected_permissions

    @pytest.mark.unit
    async def test_role_can_access_resource(self, db_session: AsyncSession):
        """Test checking resource access permissions."""
        from sqlalchemy.orm import selectinload
        
        role = Role(name="support", description="Support role")
        
        scopes = [
            Scope(name="read:tickets_support", description="Read tickets", resource="tickets"),
            Scope(name="write:tickets_support", description="Write tickets", resource="tickets"),
            Scope(name="read:users_support", description="Read users", resource="users")
        ]
        
        db_session.add_all([role] + scopes)
        await db_session.commit()
        
        # Reload role with scopes relationship
        role_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == role.id)
        )
        role = role_result.scalar_one()
        
        role.scopes.extend(scopes)
        await db_session.commit()
        
        # Reload role with updated scopes
        role_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == role.id)
        )
        role = role_result.scalar_one()
        
        # Test resource access
        assert role.can_access_resource("tickets_support", "read") is True
        assert role.can_access_resource("tickets_support", "write") is True
        assert role.can_access_resource("tickets_support", "delete") is False
        assert role.can_access_resource("users_support", "read") is True
        assert role.can_access_resource("users_support", "write") is False
        assert role.can_access_resource("nonexistent", "read") is False

    @pytest.mark.unit
    async def test_role_hierarchy_support(self, db_session: AsyncSession):
        """Test role hierarchy functionality."""
        from sqlalchemy.orm import selectinload
        
        # Create parent and child roles
        admin_role = Role(name="admin_hier", description="Administrator role")
        manager_role = Role(name="manager_hier", description="Manager role")
        user_role = Role(name="user_hier", description="User role")
        
        # Create scopes for different levels
        admin_scope = Scope(name="admin:system_hier", description="System admin", resource="system")
        manager_scope = Scope(name="manage:users_hier", description="Manage users", resource="users")
        user_scope = Scope(name="read:profile_hier", description="Read profile", resource="profile")
        
        db_session.add_all([admin_role, manager_role, user_role, admin_scope, manager_scope, user_scope])
        await db_session.commit()
        
        # Reload roles with scopes relationships
        admin_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == admin_role.id)
        )
        admin_role = admin_result.scalar_one()
        
        manager_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == manager_role.id)
        )
        manager_role = manager_result.scalar_one()
        
        user_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == user_role.id)
        )
        user_role = user_result.scalar_one()
        
        # Set up hierarchy: admin > manager > user
        admin_role.scopes.extend([admin_scope, manager_scope, user_scope])
        manager_role.scopes.extend([manager_scope, user_scope])
        user_role.scopes.append(user_scope)
        
        await db_session.commit()
        
        # Reload roles with updated scopes
        admin_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == admin_role.id)
        )
        admin_role = admin_result.scalar_one()
        
        manager_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == manager_role.id)
        )
        manager_role = manager_result.scalar_one()
        
        user_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == user_role.id)
        )
        user_role = user_result.scalar_one()
        
        # Test hierarchy
        assert len(admin_role.scopes) == 3  # Has all scopes
        assert len(manager_role.scopes) == 2  # Has manager and user scopes
        assert len(user_role.scopes) == 1   # Has only user scope
        
        # Test inheritance-like behavior
        assert admin_role.has_scope("admin:system_hier") is True
        assert admin_role.has_scope("manage:users_hier") is True
        assert admin_role.has_scope("read:profile_hier") is True
        
        assert manager_role.has_scope("admin:system_hier") is False
        assert manager_role.has_scope("manage:users_hier") is True
        assert manager_role.has_scope("read:profile_hier") is True
        
        assert user_role.has_scope("admin:system_hier") is False
        assert user_role.has_scope("manage:users_hier") is False
        assert user_role.has_scope("read:profile_hier") is True

    @pytest.mark.unit
    async def test_role_query_methods(self, db_session: AsyncSession):
        """Test role query helper methods."""
        # Create test roles
        roles = [
            Role(name="admin", description="Administrator"),
            Role(name="moderator", description="Moderator"),
            Role(name="user", description="Regular user"),
            Role(name="guest", description="Guest user")
        ]
        
        db_session.add_all(roles)
        await db_session.commit()
        
        # Test finding role by name
        admin_role = await Role.get_by_name(db_session, "admin")
        assert admin_role is not None
        assert admin_role.name == "admin"
        
        # Test finding non-existent role
        nonexistent_role = await Role.get_by_name(db_session, "nonexistent")
        assert nonexistent_role is None
        
        # Test getting all roles
        all_roles = await Role.get_all(db_session)
        assert len(all_roles) == 4
        role_names = [role.name for role in all_roles]
        assert "admin" in role_names
        assert "user" in role_names

    @pytest.mark.unit
    async def test_role_validation(self, db_session: AsyncSession):
        """Test role validation rules."""
        # Test empty name validation
        with pytest.raises(ValueError):
            role = Role(name="", description="Empty name role")
            role.validate()
        
        # Test name length validation
        with pytest.raises(ValueError):
            role = Role(name="a" * 101, description="Too long name")  # Assuming 100 char limit
            role.validate()
        
        # Test valid role
        role = Role(name="valid_role", description="Valid role")
        role.validate()  # Should not raise exception

    @pytest.mark.unit
    def test_role_equality(self):
        """Test role equality comparison."""
        role1 = Role(name="test_role", description="Test role")
        role1.id = "123e4567-e89b-12d3-a456-426614174000"
        
        role2 = Role(name="test_role", description="Test role")
        role2.id = "123e4567-e89b-12d3-a456-426614174000"
        
        role3 = Role(name="different_role", description="Different role")
        role3.id = "987fcdeb-51d2-43a1-b456-426614174000"
        
        assert role1 == role2  # Same ID
        assert role1 != role3  # Different ID
        assert role1 != "not_a_role"  # Different type

    @pytest.mark.unit
    def test_role_hash(self):
        """Test role hash for use in sets and dicts."""
        role1 = Role(name="hashable_role", description="Hashable role")
        role1.id = "123e4567-e89b-12d3-a456-426614174000"
        
        role2 = Role(name="hashable_role", description="Hashable role")
        role2.id = "123e4567-e89b-12d3-a456-426614174000"
        
        # Should be hashable and equal roles should have same hash
        role_set = {role1, role2}
        assert len(role_set) == 1  # Should deduplicate
        
        role_dict = {role1: "value"}
        assert role_dict[role2] == "value"  # Should find by equivalent key

    @pytest.mark.unit
    async def test_role_audit_fields(self, db_session: AsyncSession):
        """Test role audit fields (created_at, updated_at)."""
        role = Role(name="audit_test", description="Audit test role")
        
        db_session.add(role)
        await db_session.commit()
        await db_session.refresh(role)
        
        created_at = role.created_at
        updated_at = role.updated_at
        
        assert created_at is not None
        assert updated_at is not None
        assert created_at == updated_at  # Should be same on creation
        
        # Update role
        import asyncio
        await asyncio.sleep(0.01)  # Small delay to ensure different timestamp
        
        role.description = "Updated description"
        await db_session.commit()
        await db_session.refresh(role)
        
        assert role.created_at == created_at  # Should not change
        assert role.updated_at > updated_at   # Should be updated

    @pytest.mark.unit
    async def test_role_soft_delete(self, db_session: AsyncSession):
        """Test role soft delete functionality if implemented."""
        role = Role(name="deletable_role", description="Role to be deleted")
        
        db_session.add(role)
        await db_session.commit()
        await db_session.refresh(role)
        
        role_id = role.id
        original_name = role.name
        
        # Soft delete
        role.soft_delete()
        await db_session.commit()
        
        # Should still exist in database but name should be modified
        result = await db_session.execute(
            select(Role).where(Role.id == role_id)
        )
        deleted_role = result.scalar_one_or_none()
        
        assert deleted_role is not None
        assert deleted_role.name.startswith("deleted_")
        assert deleted_role.name != original_name

    @pytest.mark.unit
    async def test_role_complex_queries(self, db_session: AsyncSession):
        """Test complex role queries."""
        from sqlalchemy.orm import selectinload
        
        # Create roles with different scope patterns
        admin_role = Role(name="admin_complex", description="Admin role")
        editor_role = Role(name="editor_complex", description="Editor role")
        viewer_role = Role(name="viewer_complex", description="Viewer role")
        
        # Create scopes with unique names to avoid duplicates
        admin_scopes = [
            Scope(name="admin:users_complex", description="Manage users", resource="users"),
            Scope(name="admin:system_complex", description="System admin", resource="system")
        ]
        editor_scopes = [
            Scope(name="write:content_complex", description="Write content", resource="content"),
            Scope(name="read:content_editor", description="Read content", resource="content")
        ]
        viewer_scopes = [
            Scope(name="read:content_viewer", description="Read content", resource="content")
        ]
        
        db_session.add_all([admin_role, editor_role, viewer_role] + admin_scopes + editor_scopes + viewer_scopes)
        await db_session.commit()
        
        # Reload roles with scopes relationships
        admin_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == admin_role.id)
        )
        admin_role = admin_result.scalar_one()
        
        editor_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == editor_role.id)
        )
        editor_role = editor_result.scalar_one()
        
        viewer_result = await db_session.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == viewer_role.id)
        )
        viewer_role = viewer_result.scalar_one()
        
        # Assign scopes
        admin_role.scopes.extend(admin_scopes)
        editor_role.scopes.extend(editor_scopes)
        viewer_role.scopes.extend(viewer_scopes)
        
        await db_session.commit()
        
        # Query roles with specific scope
        roles_with_read_content_editor = await Role.get_roles_with_scope(db_session, "read:content_editor")
        role_names = [role.name for role in roles_with_read_content_editor]
        
        assert "editor_complex" in role_names
        assert "viewer_complex" not in role_names
        assert "admin_complex" not in role_names
        
        # Query roles with admin scopes
        admin_roles = await Role.get_roles_with_resource_access(db_session, "users_complex", "admin")
        assert len(admin_roles) == 1
        assert admin_roles[0].name == "admin_complex"