"""Integration tests for database operations with testcontainers."""

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.role import Role
from app.models.scope import Scope
from app.models.service_client import ServiceClient
from app.models.refresh_token import RefreshToken
from app.core.password import hash_password


class TestDatabaseIntegration:
    """Test database operations with real PostgreSQL container."""

    @pytest.mark.integration
    async def test_user_crud_operations(self, db_session: AsyncSession):
        """Test complete user CRUD operations."""
        # Create user
        user = User(
            username="integration_user",
            email="integration@example.com",
            password_hash=hash_password("IntegrationTest123!"),
            first_name="Integration",
            last_name="User",
        )
        
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        
        assert user.id is not None
        
        # Read user
        result = await db_session.execute(
            select(User).where(User.username == "integration_user")
        )
        found_user = result.scalar_one_or_none()
        
        assert found_user is not None
        assert found_user.email == "integration@example.com"
        
        # Update user
        found_user.first_name = "Updated"
        await db_session.commit()
        await db_session.refresh(found_user)
        
        assert found_user.first_name == "Updated"
        
        # Delete user
        await db_session.delete(found_user)
        await db_session.commit()
        
        result = await db_session.execute(
            select(User).where(User.username == "integration_user")
        )
        deleted_user = result.scalar_one_or_none()
        
        assert deleted_user is None

    @pytest.mark.integration
    async def test_role_scope_relationships(self, db_session: AsyncSession):
        """Test role-scope many-to-many relationships."""
        # Create role and scopes
        role = Role(name="test_role", description="Test role")
        scope1 = Scope(name="read:test", description="Read test", resource="test")
        scope2 = Scope(name="write:test", description="Write test", resource="test")
        
        db_session.add_all([role, scope1, scope2])
        await db_session.commit()
        await db_session.refresh(role)
        
        # Add scopes to role
        role.scopes.extend([scope1, scope2])
        await db_session.commit()
        await db_session.refresh(role)
        
        # Verify relationships
        assert len(role.scopes) == 2
        assert scope1 in role.scopes
        assert scope2 in role.scopes
        
        # Test reverse relationship
        await db_session.refresh(scope1)
        assert role in scope1.roles

    @pytest.mark.integration
    async def test_user_role_relationships(self, db_session: AsyncSession):
        """Test user-role many-to-many relationships."""
        # Create user and roles
        user = User(
            username="role_test_user",
            email="roletest@example.com",
            password_hash=hash_password("RoleTest123!"),
        )
        
        role1 = Role(name="user", description="User role")
        role2 = Role(name="admin", description="Admin role")
        
        db_session.add_all([user, role1, role2])
        await db_session.commit()
        await db_session.refresh(user)
        await db_session.refresh(role1)
        await db_session.refresh(role2)
        
        # Add roles to user
        user.roles.extend([role1, role2])
        await db_session.commit()
        await db_session.refresh(user)
        
        # Verify relationships
        assert len(user.roles) == 2
        assert await user.has_role("user") is True
        assert await user.has_role("admin") is True
        assert await user.has_role("nonexistent") is False
        
        # Test role names
        role_names = await user.get_role_names()
        assert "user" in role_names
        assert "admin" in role_names

    @pytest.mark.integration
    async def test_service_client_scope_relationships(self, db_session: AsyncSession):
        """Test service client-scope relationships."""
        # Create service client and scopes
        client = ServiceClient(
            client_id="integration-service",
            client_secret_hash=hash_password("service-secret"),
            name="Integration Service",
            description="Service for integration testing",
        )
        
        scope1 = Scope(name="service:read", description="Service read", resource="service")
        scope2 = Scope(name="service:write", description="Service write", resource="service")
        
        db_session.add_all([client, scope1, scope2])
        await db_session.commit()
        await db_session.refresh(client)
        await db_session.refresh(scope1)
        await db_session.refresh(scope2)
        
        # Add scopes to client
        client.scopes.extend([scope1, scope2])
        await db_session.commit()
        await db_session.refresh(client)
        
        # Verify relationships
        assert len(client.scopes) == 2
        assert client.has_scope("service:read") is True
        assert client.has_scope("service:write") is True
        
        # Test scope names
        scope_names = client.get_scope_names()
        assert "service:read" in scope_names
        assert "service:write" in scope_names

    @pytest.mark.integration
    async def test_refresh_token_relationships(self, db_session: AsyncSession):
        """Test refresh token relationships with users and service clients."""
        # Create user and service client
        import time
        timestamp = str(int(time.time() * 1000))  # millisecond timestamp
        user = User(
            username=f"refresh_token_user_{timestamp}",
            email=f"refresh_token_{timestamp}@example.com",
            password_hash=hash_password("TokenTest123!"),
        )
        
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        
        # Create user refresh token
        user_token = RefreshToken.create_for_user(
            user=user,
            client_id="web-client",
            scope="read:profile",
        )
        
        db_session.add(user_token)
        await db_session.commit()
        await db_session.refresh(user_token)
        
        # Verify user token relationships
        assert user_token.user_id == user.id
        assert user_token.jti is not None
        assert user_token.is_valid is True
        
        # Test token properties
        assert not user_token.is_expired
        assert not user_token.is_revoked
        assert not user_token.is_used
        assert user_token.get_remaining_lifetime() > 0

    @pytest.mark.integration
    async def test_cascade_deletions(self, db_session: AsyncSession):
        """Test cascade deletions work correctly."""
        # Create user with refresh tokens
        user = User(
            username="cascade_user",
            email="cascade@example.com",
            password_hash=hash_password("CascadeTest123!"),
        )
        
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        
        # Create refresh tokens for user
        token1 = RefreshToken.create_for_user(user=user, client_id="client1")
        token2 = RefreshToken.create_for_user(user=user, client_id="client2")
        
        db_session.add_all([token1, token2])
        await db_session.commit()
        
        # Verify tokens exist
        result = await db_session.execute(
            select(RefreshToken).where(RefreshToken.user_id == user.id)
        )
        tokens = result.scalars().all()
        assert len(tokens) == 2
        
        # Delete user
        await db_session.delete(user)
        await db_session.commit()
        
        # Verify tokens are cascade deleted
        result = await db_session.execute(
            select(RefreshToken).where(RefreshToken.user_id == user.id)
        )
        tokens = result.scalars().all()
        assert len(tokens) == 0

    @pytest.mark.integration
    async def test_unique_constraints(self, db_session: AsyncSession):
        """Test unique constraints are enforced."""
        import time
        timestamp = str(int(time.time() * 1000))  # millisecond timestamp
        
        # Create first user
        user1 = User(
            username=f"unique_user_{timestamp}",
            email=f"unique_{timestamp}@example.com",
            password_hash=hash_password("UniqueTest123!"),
        )
        
        db_session.add(user1)
        await db_session.commit()
        
        # Try to create user with same username
        user2 = User(
            username=f"unique_user_{timestamp}",  # Same username
            email=f"different_{timestamp}@example.com",
            password_hash=hash_password("UniqueTest123!"),
        )
        
        db_session.add(user2)
        
        with pytest.raises(Exception):  # Should raise integrity error
            await db_session.commit()
        
        await db_session.rollback()
        
        # Try to create user with same email
        user3 = User(
            username=f"different_user_{timestamp}",
            email=f"unique_{timestamp}@example.com",  # Same email
            password_hash=hash_password("UniqueTest123!"),
        )
        
        db_session.add(user3)
        
        with pytest.raises(Exception):  # Should raise integrity error
            await db_session.commit()
        
        await db_session.rollback()  # Ensure rollback after test

    @pytest.mark.integration
    async def test_complex_queries(self, db_session: AsyncSession):
        """Test complex database queries."""
        # Create test data
        admin_role = Role(name="admin", description="Admin role")
        user_role = Role(name="user", description="User role")
        
        admin_scope = Scope(name="admin:users", description="Manage users", resource="users")
        read_scope = Scope(name="read:profile", description="Read profile", resource="profile")
        
        admin_role.scopes.append(admin_scope)
        user_role.scopes.append(read_scope)
        
        admin_user = User(
            username="admin_user",
            email="admin@example.com",
            password_hash=hash_password("AdminTest123!"),
        )
        admin_user.roles.append(admin_role)
        
        regular_user = User(
            username="regular_user",
            email="regular@example.com",
            password_hash=hash_password("RegularTest123!"),
        )
        regular_user.roles.append(user_role)
        
        db_session.add_all([admin_role, user_role, admin_scope, read_scope, admin_user, regular_user])
        await db_session.commit()
        
        # Query users with admin role
        result = await db_session.execute(
            select(User).join(User.roles).where(Role.name == "admin")
        )
        admin_users = result.scalars().all()
        
        assert len(admin_users) == 1
        assert admin_users[0].username == "admin_user"
        
        # Query users with specific scope
        result = await db_session.execute(
            select(User)
            .join(User.roles)
            .join(Role.scopes)
            .where(Scope.name == "admin:users")
        )
        users_with_admin_scope = result.scalars().all()
        
        assert len(users_with_admin_scope) == 1
        assert users_with_admin_scope[0].username == "admin_user"

    @pytest.mark.integration
    async def test_transaction_rollback(self, db_session: AsyncSession):
        """Test transaction rollback functionality."""
        # Create user
        user = User(
            username="rollback_user",
            email="rollback@example.com",
            password_hash=hash_password("RollbackTest123!"),
        )
        
        db_session.add(user)
        await db_session.commit()
        
        # Start transaction and make changes
        user.first_name = "Modified"
        
        # Verify changes are visible in session
        assert user.first_name == "Modified"
        
        # Rollback transaction
        await db_session.rollback()
        await db_session.refresh(user)
        
        # Verify changes were rolled back
        assert user.first_name is None

    @pytest.mark.integration
    async def test_concurrent_access(self, db_session: AsyncSession):
        """Test concurrent database access patterns."""
        # Create user
        user = User(
            username="concurrent_user",
            email="concurrent@example.com",
            password_hash=hash_password("ConcurrentTest123!"),
            failed_login_attempts=0,
        )
        
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        
        # Simulate concurrent failed login attempts
        original_attempts = int(user.failed_login_attempts)
        
        # Increment attempts multiple times
        for _ in range(3):
            user.increment_failed_login()
        
        await db_session.commit()
        await db_session.refresh(user)
        
        # Verify all increments were applied
        assert int(user.failed_login_attempts) == original_attempts + 3

    @pytest.mark.integration
    @pytest.mark.slow
    async def test_large_dataset_performance(self, db_session: AsyncSession):
        """Test performance with larger datasets."""
        # Create multiple roles and scopes
        roles = []
        scopes = []
        
        for i in range(10):
            role = Role(name=f"role_{i}", description=f"Role {i}")
            scope = Scope(name=f"scope_{i}:resource", description=f"Scope {i}", resource="resource")
            roles.append(role)
            scopes.append(scope)
        
        db_session.add_all(roles + scopes)
        await db_session.commit()
        
        # Create users with various role combinations
        users = []
        for i in range(50):
            user = User(
                username=f"user_{i}",
                email=f"user_{i}@example.com",
                password_hash=hash_password(f"UserTest{i}123!"),
            )
            
            # Assign random roles
            user.roles.extend(roles[i % 3:(i % 3) + 2])
            users.append(user)
        
        db_session.add_all(users)
        await db_session.commit()
        
        # Test query performance
        import time
        start_time = time.time()
        
        # Query all users with their roles and scopes
        result = await db_session.execute(
            select(User).options(
                # Use selectin loading for better performance
                # This would be configured in the model relationships
            )
        )
        all_users = result.scalars().all()
        
        end_time = time.time()
        query_time = end_time - start_time
        
        assert len(all_users) == 50
        assert query_time < 5.0  # Should complete within 5 seconds
        
        # Verify data integrity
        for user in all_users[:5]:  # Check first 5 users
            assert len(user.roles) > 0
            role_names = await user.get_role_names()
            assert len(role_names) > 0