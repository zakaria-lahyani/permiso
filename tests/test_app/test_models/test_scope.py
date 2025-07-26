"""Tests for Scope model."""

import pytest
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.scope import Scope
from app.models.role import Role
from app.models.service_client import ServiceClient
from app.core.password import hash_password


class TestScopeModel:
    """Test Scope model functionality."""

    @pytest.mark.unit
    async def test_scope_creation(self, db_session: AsyncSession):
        """Test scope creation with all fields."""
        scope = Scope(
            name="read:articles",
            description="Read articles permission",
            resource="articles"
        )
        
        db_session.add(scope)
        await db_session.commit()
        await db_session.refresh(scope)
        
        assert scope.id is not None
        assert scope.name == "read:articles"
        assert scope.description == "Read articles permission"
        assert scope.resource == "articles"
        assert scope.created_at is not None
        assert scope.updated_at is not None
        assert isinstance(scope.created_at, datetime)

    @pytest.mark.unit
    async def test_scope_creation_minimal(self, db_session: AsyncSession):
        """Test scope creation with minimal required fields."""
        scope = Scope(name="minimal:scope")
        
        db_session.add(scope)
        await db_session.commit()
        await db_session.refresh(scope)
        
        assert scope.id is not None
        assert scope.name == "minimal:scope"
        assert scope.description is None
        assert scope.resource is None
        assert scope.created_at is not None

    @pytest.mark.unit
    async def test_scope_unique_name_constraint(self, db_session: AsyncSession):
        """Test that scope names must be unique."""
        # Create first scope
        scope1 = Scope(name="unique:scope", description="First scope")
        db_session.add(scope1)
        await db_session.commit()
        
        # Try to create second scope with same name
        scope2 = Scope(name="unique:scope", description="Second scope")
        db_session.add(scope2)
        
        with pytest.raises(Exception):  # Should raise integrity error
            await db_session.commit()
        
        await db_session.rollback()

    @pytest.mark.unit
    def test_scope_string_representation(self):
        """Test scope string representation."""
        scope = Scope(
            name="write:posts",
            description="Write posts permission",
            resource="posts"
        )
        
        expected_repr = "<Scope(name='write:posts', resource='posts')>"
        assert repr(scope) == expected_repr

    @pytest.mark.unit
    def test_scope_string_representation_no_resource(self):
        """Test scope string representation without resource."""
        scope = Scope(name="admin:system", description="System admin")
        
        expected_repr = "<Scope(name='admin:system', resource=None)>"
        assert repr(scope) == expected_repr

    @pytest.mark.unit
    async def test_scope_role_relationship(self, db_session: AsyncSession):
        """Test scope-role many-to-many relationship."""
        # Create scope and roles
        scope = Scope(
            name="manage:users",
            description="Manage users permission",
            resource="users"
        )
        role1 = Role(name="admin", description="Administrator role")
        role2 = Role(name="manager", description="Manager role")
        role3 = Role(name="user", description="Regular user role")
        
        db_session.add_all([scope, role1, role2, role3])
        await db_session.commit()
        await db_session.refresh(scope)
        
        # Add scope to roles
        role1.scopes.append(scope)
        role2.scopes.append(scope)
        await db_session.commit()
        await db_session.refresh(scope)
        
        # Test reverse relationship (scope -> roles)
        assert len(scope.roles) == 2
        role_names = [role.name for role in scope.roles]
        assert "admin" in role_names
        assert "manager" in role_names
        assert "user" not in role_names

    @pytest.mark.unit
    async def test_scope_service_client_relationship(self, db_session: AsyncSession):
        """Test scope-service client many-to-many relationship."""
        # Create scope and service clients
        scope = Scope(
            name="api:access",
            description="API access permission",
            resource="api"
        )
        client1 = ServiceClient(
            client_id="web-app",
            client_secret_hash=hash_password("web-secret"),
            name="Web Application"
        )
        client2 = ServiceClient(
            client_id="mobile-app",
            client_secret_hash=hash_password("mobile-secret"),
            name="Mobile Application"
        )
        
        db_session.add_all([scope, client1, client2])
        await db_session.commit()
        await db_session.refresh(scope)
        
        # Add scope to clients
        client1.scopes.append(scope)
        client2.scopes.append(scope)
        await db_session.commit()
        await db_session.refresh(scope)
        
        # Test reverse relationship (scope -> service clients)
        assert len(scope.service_clients) == 2
        client_names = [client.name for client in scope.service_clients]
        assert "Web Application" in client_names
        assert "Mobile Application" in client_names

    @pytest.mark.unit
    async def test_scope_cascade_behavior(self, db_session: AsyncSession):
        """Test scope cascade behavior with relationships."""
        # Create scope with roles and service clients
        scope = Scope(
            name="temp:scope",
            description="Temporary scope",
            resource="temp"
        )
        role = Role(name="temp_role", description="Temporary role")
        client = ServiceClient(
            client_id="temp-client",
            client_secret_hash=hash_password("temp-secret"),
            name="Temporary Client"
        )
        
        db_session.add_all([scope, role, client])
        await db_session.commit()
        
        # Create relationships
        role.scopes.append(scope)
        client.scopes.append(scope)
        await db_session.commit()
        
        # Delete scope
        await db_session.delete(scope)
        await db_session.commit()
        
        # Check that relationships are cleaned up but related entities remain
        await db_session.refresh(role)
        await db_session.refresh(client)
        
        assert len(role.scopes) == 0
        assert len(client.scopes) == 0

    @pytest.mark.unit
    def test_scope_to_dict(self):
        """Test scope to_dict method."""
        scope = Scope(
            name="delete:comments",
            description="Delete comments permission",
            resource="comments"
        )
        scope.id = "123e4567-e89b-12d3-a456-426614174000"
        scope.created_at = datetime(2024, 1, 1, 12, 0, 0)
        scope.updated_at = datetime(2024, 1, 1, 12, 0, 0)
        
        scope_dict = scope.to_dict()
        
        expected_keys = ["id", "name", "description", "resource", "created_at", "updated_at"]
        for key in expected_keys:
            assert key in scope_dict
        
        assert scope_dict["name"] == "delete:comments"
        assert scope_dict["description"] == "Delete comments permission"
        assert scope_dict["resource"] == "comments"

    @pytest.mark.unit
    def test_scope_parse_name(self):
        """Test parsing scope name into action and resource."""
        # Test standard format
        scope = Scope(name="read:users")
        action, resource = scope.parse_name()
        assert action == "read"
        assert resource == "users"
        
        # Test with complex resource
        scope = Scope(name="admin:user_profiles")
        action, resource = scope.parse_name()
        assert action == "admin"
        assert resource == "user_profiles"
        
        # Test without separator
        scope = Scope(name="system_admin")
        action, resource = scope.parse_name()
        assert action == "system_admin"
        assert resource is None
        
        # Test with multiple separators
        scope = Scope(name="read:user:profile")
        action, resource = scope.parse_name()
        assert action == "read"
        assert resource == "user:profile"

    @pytest.mark.unit
    def test_scope_get_action(self):
        """Test getting action from scope name."""
        scope1 = Scope(name="write:articles")
        assert scope1.get_action() == "write"
        
        scope2 = Scope(name="admin:system")
        assert scope2.get_action() == "admin"
        
        scope3 = Scope(name="full_access")
        assert scope3.get_action() == "full_access"

    @pytest.mark.unit
    def test_scope_get_resource(self):
        """Test getting resource from scope name."""
        scope1 = Scope(name="read:posts", resource="posts")
        # Should prefer explicit resource field
        assert scope1.get_resource() == "posts"
        
        scope2 = Scope(name="write:comments")
        # Should parse from name if resource field is None
        assert scope2.get_resource() == "comments"
        
        scope3 = Scope(name="system_admin")
        # Should return None if no resource can be determined
        assert scope3.get_resource() is None

    @pytest.mark.unit
    def test_scope_matches_pattern(self):
        """Test scope pattern matching."""
        scope = Scope(name="read:user_profiles", resource="user_profiles")
        
        # Exact match
        assert scope.matches_pattern("read:user_profiles") is True
        
        # Action wildcard
        assert scope.matches_pattern("*:user_profiles") is True
        
        # Resource wildcard
        assert scope.matches_pattern("read:*") is True
        
        # Full wildcard
        assert scope.matches_pattern("*:*") is True
        
        # No match
        assert scope.matches_pattern("write:user_profiles") is False
        assert scope.matches_pattern("read:posts") is False

    @pytest.mark.unit
    def test_scope_implies(self):
        """Test scope implication logic."""
        # Admin scope should imply read/write scopes
        admin_scope = Scope(name="admin:users", resource="users")
        read_scope = Scope(name="read:users", resource="users")
        write_scope = Scope(name="write:users", resource="users")
        delete_scope = Scope(name="delete:users", resource="users")
        
        assert admin_scope.implies(read_scope) is True
        assert admin_scope.implies(write_scope) is True
        assert admin_scope.implies(delete_scope) is True
        
        # Write scope should imply read scope
        assert write_scope.implies(read_scope) is True
        
        # Read scope should not imply write scope
        assert read_scope.implies(write_scope) is False
        
        # Different resources should not imply each other
        posts_scope = Scope(name="read:posts", resource="posts")
        assert read_scope.implies(posts_scope) is False

    @pytest.mark.unit
    async def test_scope_query_methods(self, db_session: AsyncSession):
        """Test scope query helper methods."""
        # Create test scopes
        scopes = [
            Scope(name="read:articles", resource="articles"),
            Scope(name="write:articles", resource="articles"),
            Scope(name="admin:articles", resource="articles"),
            Scope(name="read:comments", resource="comments"),
            Scope(name="system:admin", resource="system")
        ]
        
        db_session.add_all(scopes)
        await db_session.commit()
        
        # Test finding scope by name
        read_articles = await Scope.get_by_name(db_session, "read:articles")
        assert read_articles is not None
        assert read_articles.name == "read:articles"
        
        # Test finding non-existent scope
        nonexistent = await Scope.get_by_name(db_session, "nonexistent:scope")
        assert nonexistent is None
        
        # Test getting scopes by resource
        article_scopes = await Scope.get_by_resource(db_session, "articles")
        assert len(article_scopes) == 3
        scope_names = [scope.name for scope in article_scopes]
        assert "read:articles" in scope_names
        assert "write:articles" in scope_names
        assert "admin:articles" in scope_names
        
        # Test getting scopes by action
        read_scopes = await Scope.get_by_action(db_session, "read")
        assert len(read_scopes) == 2
        scope_names = [scope.name for scope in read_scopes]
        assert "read:articles" in scope_names
        assert "read:comments" in scope_names

    @pytest.mark.unit
    def test_scope_validation(self):
        """Test scope validation rules."""
        # Test empty name validation
        with pytest.raises(ValueError):
            scope = Scope(name="")
            scope.validate()
        
        # Test invalid name format
        with pytest.raises(ValueError):
            scope = Scope(name="invalid name with spaces")
            scope.validate()
        
        # Test name length validation
        with pytest.raises(ValueError):
            scope = Scope(name="a" * 201)  # Assuming 200 char limit
            scope.validate()
        
        # Test valid scope
        scope = Scope(name="valid:scope", resource="resource")
        scope.validate()  # Should not raise exception

    @pytest.mark.unit
    def test_scope_equality(self):
        """Test scope equality comparison."""
        scope1 = Scope(name="test:scope", resource="test")
        scope1.id = "123e4567-e89b-12d3-a456-426614174000"
        
        scope2 = Scope(name="test:scope", resource="test")
        scope2.id = "123e4567-e89b-12d3-a456-426614174000"
        
        scope3 = Scope(name="different:scope", resource="different")
        scope3.id = "987fcdeb-51d2-43a1-b456-426614174000"
        
        assert scope1 == scope2  # Same ID
        assert scope1 != scope3  # Different ID
        assert scope1 != "not_a_scope"  # Different type

    @pytest.mark.unit
    def test_scope_hash(self):
        """Test scope hash for use in sets and dicts."""
        scope1 = Scope(name="hashable:scope", resource="hashable")
        scope1.id = "123e4567-e89b-12d3-a456-426614174000"
        
        scope2 = Scope(name="hashable:scope", resource="hashable")
        scope2.id = "123e4567-e89b-12d3-a456-426614174000"
        
        # Should be hashable and equal scopes should have same hash
        scope_set = {scope1, scope2}
        assert len(scope_set) == 1  # Should deduplicate
        
        scope_dict = {scope1: "value"}
        assert scope_dict[scope2] == "value"  # Should find by equivalent key

    @pytest.mark.unit
    def test_scope_ordering(self):
        """Test scope ordering for consistent sorting."""
        scopes = [
            Scope(name="write:posts"),
            Scope(name="admin:system"),
            Scope(name="read:articles"),
            Scope(name="delete:comments")
        ]
        
        # Sort by name
        sorted_scopes = sorted(scopes, key=lambda s: s.name)
        expected_order = ["admin:system", "delete:comments", "read:articles", "write:posts"]
        actual_order = [scope.name for scope in sorted_scopes]
        
        assert actual_order == expected_order

    @pytest.mark.unit
    async def test_scope_audit_fields(self, db_session: AsyncSession):
        """Test scope audit fields (created_at, updated_at)."""
        scope = Scope(name="audit:test", description="Audit test scope")
        
        db_session.add(scope)
        await db_session.commit()
        await db_session.refresh(scope)
        
        created_at = scope.created_at
        updated_at = scope.updated_at
        
        assert created_at is not None
        assert updated_at is not None
        assert created_at == updated_at  # Should be same on creation
        
        # Update scope
        import asyncio
        await asyncio.sleep(0.01)  # Small delay to ensure different timestamp
        
        scope.description = "Updated description"
        await db_session.commit()
        await db_session.refresh(scope)
        
        assert scope.created_at == created_at  # Should not change
        assert scope.updated_at > updated_at   # Should be updated

    @pytest.mark.unit
    def test_scope_permission_levels(self):
        """Test scope permission level hierarchy."""
        # Define permission levels
        read_scope = Scope(name="read:data", resource="data")
        write_scope = Scope(name="write:data", resource="data")
        admin_scope = Scope(name="admin:data", resource="data")
        
        # Test permission level comparison
        assert read_scope.get_permission_level() == 1
        assert write_scope.get_permission_level() == 2
        assert admin_scope.get_permission_level() == 3
        
        # Test permission hierarchy
        assert admin_scope.has_permission_level_of(write_scope) is True
        assert admin_scope.has_permission_level_of(read_scope) is True
        assert write_scope.has_permission_level_of(read_scope) is True
        assert read_scope.has_permission_level_of(write_scope) is False

    @pytest.mark.unit
    async def test_scope_usage_tracking(self, db_session: AsyncSession):
        """Test scope usage tracking."""
        scope = Scope(name="tracked:scope", resource="tracked")
        role = Role(name="tracking_role", description="Role for tracking")
        client = ServiceClient(
            client_id="tracking-client",
            client_secret_hash=hash_password("tracking-secret"),
            name="Tracking Client"
        )
        
        db_session.add_all([scope, role, client])
        await db_session.commit()
        
        # Assign scope to role and client
        role.scopes.append(scope)
        client.scopes.append(scope)
        await db_session.commit()
        await db_session.refresh(scope)
        
        # Test usage count
        usage_count = scope.get_usage_count()
        assert usage_count == 2  # Used by 1 role + 1 client
        
        # Test if scope is in use
        assert scope.is_in_use() is True
        
        # Test getting entities using this scope
        using_entities = scope.get_using_entities()
        assert len(using_entities["roles"]) == 1
        assert len(using_entities["service_clients"]) == 1

    @pytest.mark.unit
    async def test_scope_complex_queries(self, db_session: AsyncSession):
        """Test complex scope queries."""
        # Create scopes with different patterns
        scopes = [
            Scope(name="read:user_profiles", resource="user_profiles"),
            Scope(name="write:user_profiles", resource="user_profiles"),
            Scope(name="admin:user_profiles", resource="user_profiles"),
            Scope(name="read:system_logs", resource="system_logs"),
            Scope(name="admin:system_logs", resource="system_logs"),
            Scope(name="system:maintenance", resource="system")
        ]
        
        db_session.add_all(scopes)
        await db_session.commit()
        
        # Query scopes with admin action
        admin_scopes = await Scope.get_admin_scopes(db_session)
        admin_names = [scope.name for scope in admin_scopes]
        assert "admin:user_profiles" in admin_names
        assert "admin:system_logs" in admin_names
        assert "read:user_profiles" not in admin_names
        
        # Query scopes for specific resource pattern
        user_scopes = await Scope.get_scopes_for_resource_pattern(db_session, "user_*")
        user_scope_names = [scope.name for scope in user_scopes]
        assert "read:user_profiles" in user_scope_names
        assert "write:user_profiles" in user_scope_names
        assert "admin:user_profiles" in user_scope_names
        assert "read:system_logs" not in user_scope_names
        
        # Query scopes by permission level
        high_permission_scopes = await Scope.get_scopes_by_min_permission_level(db_session, 3)
        high_perm_names = [scope.name for scope in high_permission_scopes]
        assert "admin:user_profiles" in high_perm_names
        assert "admin:system_logs" in high_perm_names
        assert "system:maintenance" in high_perm_names
        assert "read:user_profiles" not in high_perm_names

    @pytest.mark.unit
    def test_scope_serialization(self):
        """Test scope serialization for API responses."""
        scope = Scope(
            name="api:access",
            description="API access permission",
            resource="api"
        )
        scope.id = "123e4567-e89b-12d3-a456-426614174000"
        
        # Test basic serialization
        serialized = scope.serialize()
        assert serialized["name"] == "api:access"
        assert serialized["description"] == "API access permission"
        assert serialized["resource"] == "api"
        assert serialized["action"] == "api"
        
        # Test serialization with metadata
        serialized_with_meta = scope.serialize(include_metadata=True)
        assert "created_at" in serialized_with_meta
        assert "updated_at" in serialized_with_meta
        assert "id" in serialized_with_meta
        
        # Test serialization for public API
        public_serialized = scope.serialize_for_public()
        assert "id" not in public_serialized  # Should not expose internal ID
        assert public_serialized["name"] == "api:access"
        assert public_serialized["description"] == "API access permission"

    @pytest.mark.unit
    def test_scope_security_classification(self):
        """Test scope security classification."""
        # Test different security levels
        public_scope = Scope(name="read:public_info", resource="public_info")
        assert public_scope.get_security_level() == "public"
        
        user_scope = Scope(name="read:user_profile", resource="user_profile")
        assert user_scope.get_security_level() == "user"
        
        admin_scope = Scope(name="admin:users", resource="users")
        assert admin_scope.get_security_level() == "admin"
        
        system_scope = Scope(name="system:maintenance", resource="system")
        assert system_scope.get_security_level() == "system"
        
        # Test security level comparison
        assert system_scope.is_more_privileged_than(admin_scope) is True
        assert admin_scope.is_more_privileged_than(user_scope) is True
        assert user_scope.is_more_privileged_than(public_scope) is True
        assert public_scope.is_more_privileged_than(system_scope) is False