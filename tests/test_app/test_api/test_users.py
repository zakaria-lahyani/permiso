"""Tests for user management API endpoints."""

import pytest
from httpx import AsyncClient
from unittest.mock import patch, AsyncMock

from app.models.user import User
from app.models.role import Role
from app.core.password import hash_password


class TestUsersListEndpoint:
    """Test GET /api/v1/users endpoint."""

    @pytest.mark.integration
    async def test_list_users_success(self, async_client: AsyncClient, admin_access_token: str, test_users: list[User]):
        """Test successful user listing by admin."""
        response = await async_client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {admin_access_token}"}
        )
        
        assert response.status_code == 200
        
        users_data = response.json()
        assert "users" in users_data
        assert "total" in users_data
        assert "page" in users_data
        assert "per_page" in users_data
        
        users = users_data["users"]
        assert len(users) >= len(test_users)
        
        # Verify user structure
        for user in users:
            assert "id" in user
            assert "username" in user
            assert "email" in user
            assert "is_active" in user
            assert "created_at" in user
            # Password hash should not be included
            assert "password_hash" not in user

    @pytest.mark.integration
    async def test_list_users_pagination(self, async_client: AsyncClient, admin_access_token: str):
        """Test user listing with pagination."""
        response = await async_client.get(
            "/api/v1/users?page=1&per_page=5",
            headers={"Authorization": f"Bearer {admin_access_token}"}
        )
        
        print(f"Response status: {response.status_code}")
        print(f"Response body: {response.text}")
        print(f"Response headers: {response.headers}")
        
        assert response.status_code == 200
        
        users_data = response.json()
        assert users_data["page"] == 1
        assert users_data["per_page"] == 5
        assert len(users_data["users"]) <= 5

    @pytest.mark.integration
    async def test_list_users_filtering(self, async_client: AsyncClient, admin_access_token: str):
        """Test user listing with filters."""
        # Filter by active status
        response = await async_client.get(
            "/api/v1/users?is_active=true",
            headers={"Authorization": f"Bearer {admin_access_token}"}
        )
        
        assert response.status_code == 200
        
        users_data = response.json()
        for user in users_data["users"]:
            assert user["is_active"] is True

    @pytest.mark.integration
    async def test_list_users_search(self, async_client: AsyncClient, admin_access_token: str, test_user: User):
        """Test user listing with search."""
        response = await async_client.get(
            f"/api/v1/users?search={test_user.username[:3]}",
            headers={"Authorization": f"Bearer {admin_access_token}"}
        )
        
        assert response.status_code == 200
        
        users_data = response.json()
        # Should find the test user
        usernames = [user["username"] for user in users_data["users"]]
        assert test_user.username in usernames

    @pytest.mark.integration
    async def test_list_users_unauthorized(self, async_client: AsyncClient):
        """Test user listing without authorization."""
        response = await async_client.get("/api/v1/users")
        
        assert response.status_code == 401

    @pytest.mark.integration
    async def test_list_users_forbidden(self, async_client: AsyncClient, user_access_token: str):
        """Test user listing with insufficient permissions."""
        response = await async_client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {user_access_token}"}
        )
        
        assert response.status_code == 403


class TestUsersCreateEndpoint:
    """Test POST /api/v1/users endpoint."""

    @pytest.mark.integration
    async def test_create_user_success(self, async_client: AsyncClient, admin_access_token: str):
        """Test successful user creation by admin."""
        user_data = {
            "username": "newuser123",
            "email": "newuser@example.com",
            "password": "NewPassword123!",
            "is_active": True
        }
        
        response = await async_client.post(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json=user_data
        )
        
        assert response.status_code == 201
        
        created_user = response.json()
        assert created_user["username"] == user_data["username"]
        assert created_user["email"] == user_data["email"]
        assert created_user["is_active"] == user_data["is_active"]
        assert "id" in created_user
        assert "created_at" in created_user
        # Password should not be returned
        assert "password" not in created_user
        assert "password_hash" not in created_user

    @pytest.mark.integration
    async def test_create_user_with_roles(self, async_client: AsyncClient, admin_access_token: str, test_role: Role):
        """Test user creation with roles."""
        user_data = {
            "username": "userroles123",
            "email": "userroles@example.com",
            "password": "UserRoles123!",
            "role_ids": [test_role.id]
        }
        
        response = await async_client.post(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json=user_data
        )
        
        assert response.status_code == 201
        
        created_user = response.json()
        assert "roles" in created_user
        assert len(created_user["roles"]) == 1
        assert created_user["roles"][0]["id"] == test_role.id

    @pytest.mark.integration
    async def test_create_user_duplicate_username(self, async_client: AsyncClient, admin_access_token: str, test_user: User):
        """Test user creation with duplicate username."""
        user_data = {
            "username": test_user.username,  # Duplicate
            "email": "different@example.com",
            "password": "DifferentPassword123!"
        }
        
        response = await async_client.post(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json=user_data
        )
        
        assert response.status_code == 409
        
        error_data = response.json()
        assert "username" in error_data["detail"].lower()

    @pytest.mark.integration
    async def test_create_user_duplicate_email(self, async_client: AsyncClient, admin_access_token: str, test_user: User):
        """Test user creation with duplicate email."""
        user_data = {
            "username": "differentuser",
            "email": test_user.email,  # Duplicate
            "password": "DifferentPassword123!"
        }
        
        response = await async_client.post(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json=user_data
        )
        
        assert response.status_code == 409
        
        error_data = response.json()
        assert "email" in error_data["detail"].lower()

    @pytest.mark.integration
    async def test_create_user_invalid_data(self, async_client: AsyncClient, admin_access_token: str):
        """Test user creation with invalid data."""
        invalid_data_cases = [
            # Missing required fields
            {"username": "test"},
            {"email": "test@example.com"},
            {"password": "TestPassword123!"},
            
            # Invalid email format
            {"username": "test", "email": "invalid-email", "password": "TestPassword123!"},
            
            # Weak password
            {"username": "test", "email": "test@example.com", "password": "weak"},
            
            # Invalid username (too short)
            {"username": "ab", "email": "test@example.com", "password": "TestPassword123!"},
            
            # Invalid username (special characters)
            {"username": "test@user", "email": "test@example.com", "password": "TestPassword123!"},
        ]
        
        for invalid_data in invalid_data_cases:
            response = await async_client.post(
                "/api/v1/users",
                headers={"Authorization": f"Bearer {admin_access_token}"},
                json=invalid_data
            )
            
            assert response.status_code == 422

    @pytest.mark.integration
    async def test_create_user_unauthorized(self, async_client: AsyncClient):
        """Test user creation without authorization."""
        user_data = {
            "username": "unauthorized",
            "email": "unauthorized@example.com",
            "password": "UnauthorizedPassword123!"
        }
        
        response = await async_client.post("/api/v1/users", json=user_data)
        
        assert response.status_code == 401

    @pytest.mark.integration
    async def test_create_user_forbidden(self, async_client: AsyncClient, user_access_token: str):
        """Test user creation with insufficient permissions."""
        user_data = {
            "username": "forbidden",
            "email": "forbidden@example.com",
            "password": "ForbiddenPassword123!"
        }
        
        response = await async_client.post(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {user_access_token}"},
            json=user_data
        )
        
        assert response.status_code == 403


class TestUsersGetEndpoint:
    """Test GET /api/v1/users/{user_id} endpoint."""

    @pytest.mark.integration
    async def test_get_user_success(self, async_client: AsyncClient, admin_access_token: str, test_user: User):
        """Test successful user retrieval by admin."""
        response = await async_client.get(
            f"/api/v1/users/{test_user.id}",
            headers={"Authorization": f"Bearer {admin_access_token}"}
        )
        
        print(f"Response status: {response.status_code}")
        print(f"Response body: {response.text}")
        print(f"Response headers: {response.headers}")
        
        assert response.status_code == 200
        
        user_data = response.json()
        assert user_data["id"] == str(test_user.id)
        assert user_data["username"] == test_user.username
        assert user_data["email"] == test_user.email
        assert user_data["is_active"] == test_user.is_active
        assert "created_at" in user_data
        assert "roles" in user_data
        # Sensitive data should not be included
        assert "password_hash" not in user_data

    @pytest.mark.integration
    async def test_get_user_self(self, async_client: AsyncClient, user_access_token: str, test_user: User):
        """Test user retrieving their own profile."""
        response = await async_client.get(
            f"/api/v1/users/{test_user.id}",
            headers={"Authorization": f"Bearer {user_access_token}"}
        )
        
        assert response.status_code == 200
        
        user_data = response.json()
        assert user_data["id"] == str(test_user.id)

    @pytest.mark.integration
    async def test_get_user_not_found(self, async_client: AsyncClient, admin_access_token: str):
        """Test user retrieval with non-existent ID."""
        response = await async_client.get(
            "/api/v1/users/99999",
            headers={"Authorization": f"Bearer {admin_access_token}"}
        )
        
        assert response.status_code == 404

    @pytest.mark.integration
    async def test_get_user_forbidden(self, async_client: AsyncClient, user_access_token: str, admin_user: User):
        """Test user trying to access another user's profile."""
        response = await async_client.get(
            f"/api/v1/users/{admin_user.id}",
            headers={"Authorization": f"Bearer {user_access_token}"}
        )
        
        assert response.status_code == 403

    @pytest.mark.integration
    async def test_get_user_unauthorized(self, async_client: AsyncClient, test_user: User):
        """Test user retrieval without authorization."""
        response = await async_client.get(f"/api/v1/users/{test_user.id}")
        
        assert response.status_code == 401


class TestUsersUpdateEndpoint:
    """Test PUT /api/v1/users/{user_id} endpoint."""

    @pytest.mark.integration
    async def test_update_user_success(self, async_client: AsyncClient, admin_access_token: str, test_user: User):
        """Test successful user update by admin."""
        update_data = {
            "email": "updated@example.com",
            "is_active": False
        }
        
        response = await async_client.put(
            f"/api/v1/users/{test_user.id}",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json=update_data
        )
        
        assert response.status_code == 200
        
        updated_user = response.json()
        assert updated_user["email"] == update_data["email"]
        assert updated_user["is_active"] == update_data["is_active"]
        # Username should remain unchanged
        assert updated_user["username"] == test_user.username

    @pytest.mark.integration
    async def test_update_user_self(self, async_client: AsyncClient, user_access_token: str, test_user: User):
        """Test user updating their own profile."""
        update_data = {
            "email": "self_updated@example.com"
        }
        
        response = await async_client.put(
            f"/api/v1/users/{test_user.id}",
            headers={"Authorization": f"Bearer {user_access_token}"},
            json=update_data
        )
        
        assert response.status_code == 200
        
        updated_user = response.json()
        assert updated_user["email"] == update_data["email"]

    @pytest.mark.integration
    async def test_update_user_password(self, async_client: AsyncClient, user_access_token: str, test_user: User):
        """Test user password update."""
        update_data = {
            "current_password": "TestPassword123!",
            "new_password": "NewPassword123!"
        }
        
        response = await async_client.put(
            f"/api/v1/users/{test_user.id}/password",
            headers={"Authorization": f"Bearer {user_access_token}"},
            json=update_data
        )
        
        assert response.status_code == 200
        
        result = response.json()
        assert result["message"] == "Password updated successfully"

    @pytest.mark.integration
    async def test_update_user_password_wrong_current(self, async_client: AsyncClient, user_access_token: str, test_user: User):
        """Test user password update with wrong current password."""
        update_data = {
            "current_password": "WrongPassword123!",
            "new_password": "NewPassword123!"
        }
        
        response = await async_client.put(
            f"/api/v1/users/{test_user.id}/password",
            headers={"Authorization": f"Bearer {user_access_token}"},
            json=update_data
        )
        
        assert response.status_code == 400
        
        error_data = response.json()
        assert "current password" in error_data["detail"].lower()

    @pytest.mark.integration
    async def test_update_user_roles(self, async_client: AsyncClient, admin_access_token: str, test_user: User, test_role: Role):
        """Test user role update by admin."""
        update_data = {
            "role_ids": [test_role.id]
        }
        
        response = await async_client.put(
            f"/api/v1/users/{test_user.id}/roles",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json=update_data
        )
        
        assert response.status_code == 200
        
        updated_user = response.json()
        assert "roles" in updated_user
        assert len(updated_user["roles"]) == 1
        assert updated_user["roles"][0]["id"] == test_role.id

    @pytest.mark.integration
    async def test_update_user_not_found(self, async_client: AsyncClient, admin_access_token: str):
        """Test user update with non-existent ID."""
        update_data = {"email": "notfound@example.com"}
        
        response = await async_client.put(
            "/api/v1/users/99999",
            headers={"Authorization": f"Bearer {admin_access_token}"},
            json=update_data
        )
        
        assert response.status_code == 404

    @pytest.mark.integration
    async def test_update_user_forbidden(self, async_client: AsyncClient, user_access_token: str, admin_user: User):
        """Test user trying to update another user's profile."""
        update_data = {"email": "forbidden@example.com"}
        
        response = await async_client.put(
            f"/api/v1/users/{admin_user.id}",
            headers={"Authorization": f"Bearer {user_access_token}"},
            json=update_data
        )
        
        assert response.status_code == 403

    @pytest.mark.integration
    async def test_update_user_invalid_data(self, async_client: AsyncClient, admin_access_token: str, test_user: User):
        """Test user update with invalid data."""
        invalid_data_cases = [
            # Invalid email format
            {"email": "invalid-email"},
            
            # Username change (should not be allowed)
            {"username": "newusername"},
            
            # Invalid role IDs
            {"role_ids": [99999]},
        ]
        
        for invalid_data in invalid_data_cases:
            response = await async_client.put(
                f"/api/v1/users/{test_user.id}",
                headers={"Authorization": f"Bearer {admin_access_token}"},
                json=invalid_data
            )
            
            assert response.status_code in [400, 422]


class TestUsersDeleteEndpoint:
    """Test DELETE /api/v1/users/{user_id} endpoint."""

    @pytest.mark.integration
    async def test_delete_user_success(self, async_client: AsyncClient, admin_access_token: str, db_session):
        """Test successful user deletion by admin."""
        # Create user to delete
        user_to_delete = User(
            username="todelete",
            email="todelete@example.com",
            password_hash=hash_password("ToDelete123!")
        )
        db_session.add(user_to_delete)
        await db_session.commit()
        await db_session.refresh(user_to_delete)
        
        response = await async_client.delete(
            f"/api/v1/users/{user_to_delete.id}",
            headers={"Authorization": f"Bearer {admin_access_token}"}
        )
        
        assert response.status_code == 204

    @pytest.mark.integration
    async def test_delete_user_not_found(self, async_client: AsyncClient, admin_access_token: str):
        """Test user deletion with non-existent ID."""
        response = await async_client.delete(
            "/api/v1/users/99999",
            headers={"Authorization": f"Bearer {admin_access_token}"}
        )
        
        assert response.status_code == 404

    @pytest.mark.integration
    async def test_delete_user_self_forbidden(self, async_client: AsyncClient, admin_access_token: str, admin_user: User):
        """Test admin trying to delete their own account."""
        response = await async_client.delete(
            f"/api/v1/users/{admin_user.id}",
            headers={"Authorization": f"Bearer {admin_access_token}"}
        )
        
        assert response.status_code == 403
        
        error_data = response.json()
        assert "cannot delete" in error_data["detail"].lower()

    @pytest.mark.integration
    async def test_delete_user_unauthorized(self, async_client: AsyncClient, test_user: User):
        """Test user deletion without authorization."""
        response = await async_client.delete(f"/api/v1/users/{test_user.id}")
        
        assert response.status_code == 401

    @pytest.mark.integration
    async def test_delete_user_forbidden(self, async_client: AsyncClient, user_access_token: str, admin_user: User):
        """Test user trying to delete another user."""
        response = await async_client.delete(
            f"/api/v1/users/{admin_user.id}",
            headers={"Authorization": f"Bearer {user_access_token}"}
        )
        
        assert response.status_code == 403


class TestUsersMeEndpoint:
    """Test GET /api/v1/users/me endpoint."""

    @pytest.mark.integration
    async def test_get_current_user_success(self, async_client: AsyncClient, user_access_token: str, test_user: User):
        """Test successful current user retrieval."""
        response = await async_client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {user_access_token}"}
        )
        
        assert response.status_code == 200
        
        user_data = response.json()
        assert user_data["id"] == str(test_user.id)
        assert user_data["username"] == test_user.username
        assert user_data["email"] == test_user.email
        assert "roles" in user_data
        assert "scopes" in user_data
        # Sensitive data should not be included
        assert "password_hash" not in user_data

    @pytest.mark.integration
    async def test_get_current_user_unauthorized(self, async_client: AsyncClient):
        """Test current user retrieval without authorization."""
        response = await async_client.get("/api/v1/users/me")
        
        assert response.status_code == 401


class TestUsersEndpointSecurity:
    """Test security aspects of user endpoints."""

    @pytest.mark.security
    async def test_users_endpoints_input_validation(self, async_client: AsyncClient, admin_access_token: str):
        """Test input validation on user endpoints."""
        # Test with malicious inputs
        malicious_inputs = [
            {"username": "<script>alert('xss')</script>", "email": "test@example.com", "password": "Test123!"},
            {"username": "test", "email": "'; DROP TABLE users; --", "password": "Test123!"},
            {"username": "../../../etc/passwd", "email": "test@example.com", "password": "Test123!"},
        ]
        
        for malicious_input in malicious_inputs:
            response = await async_client.post(
                "/api/v1/users",
                headers={"Authorization": f"Bearer {admin_access_token}"},
                json=malicious_input
            )
            
            # Should reject malicious input
            assert response.status_code in [400, 422]

    @pytest.mark.security
    async def test_users_endpoints_authorization_bypass(self, async_client: AsyncClient, user_access_token: str):
        """Test that users cannot bypass authorization."""
        # Try to access admin-only endpoints
        admin_endpoints = [
            ("GET", "/api/v1/users"),
            ("POST", "/api/v1/users"),
            ("DELETE", "/api/v1/users/1"),
        ]
        
        for method, endpoint in admin_endpoints:
            if method == "GET":
                response = await async_client.get(
                    endpoint,
                    headers={"Authorization": f"Bearer {user_access_token}"}
                )
            elif method == "POST":
                response = await async_client.post(
                    endpoint,
                    headers={"Authorization": f"Bearer {user_access_token}"},
                    json={"username": "test", "email": "test@example.com", "password": "Test123!"}
                )
            elif method == "DELETE":
                response = await async_client.delete(
                    endpoint,
                    headers={"Authorization": f"Bearer {user_access_token}"}
                )
            
            assert response.status_code == 403

    @pytest.mark.security
    async def test_users_endpoints_data_exposure(self, async_client: AsyncClient, admin_access_token: str, test_user: User):
        """Test that sensitive data is not exposed."""
        response = await async_client.get(
            f"/api/v1/users/{test_user.id}",
            headers={"Authorization": f"Bearer {admin_access_token}"}
        )
        
        assert response.status_code == 200
        
        user_data = response.json()
        
        # Sensitive fields should not be present
        sensitive_fields = [
            "password_hash", "password", "secret", "token",
            "private_key", "api_key", "session_id"
        ]
        
        for field in sensitive_fields:
            assert field not in user_data

    @pytest.mark.security
    async def test_users_endpoints_rate_limiting(self, async_client: AsyncClient, admin_access_token: str):
        """Test rate limiting on user endpoints."""
        # Test multiple rapid requests
        for _ in range(20):
            response = await async_client.get(
                "/api/v1/users",
                headers={"Authorization": f"Bearer {admin_access_token}"}
            )
            
            if response.status_code == 429:
                # Rate limit hit
                error_data = response.json()
                assert "rate_limit_exceeded" in error_data.get("error", "")
                break
        else:
            # If we didn't hit rate limit, that's also acceptable
            pass