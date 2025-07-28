"""User management functional tests."""

import pytest
import uuid
from conftest import (
    PermisoClient,
    USER_USERNAME,
    USER_PASSWORD,
    assert_valid_user_response,
    assert_error_response
)


class TestUserManagement:
    """Test user management functionality."""
    
    def test_user_registration_success(self, client, test_user_data):
        """Test successful user registration."""
        response = client.post("/users/register", json=test_user_data)
        
        assert response.status_code == 201, \
            f"User registration failed: {response.status_code} - {response.text}"
        
        user_response = response.json()
        assert_valid_user_response(user_response, test_user_data["username"])
        
        # Verify all provided data is correctly stored
        assert user_response["email"] == test_user_data["email"]
        assert user_response["first_name"] == test_user_data["first_name"]
        assert user_response["last_name"] == test_user_data["last_name"]
        assert user_response["display_name"] == test_user_data["display_name"]
        assert user_response["bio"] == test_user_data["bio"]
        
        # New users should be active but not verified by default
        assert user_response["is_active"] is True
        assert user_response.get("is_verified", False) is False
    
    def test_user_registration_duplicate_username(self, client, test_user_data):
        """Test user registration with duplicate username."""
        # Register first user
        response = client.post("/users/register", json=test_user_data)
        assert response.status_code == 201, "First registration failed"
        
        # Try to register with same username but different email
        duplicate_data = test_user_data.copy()
        duplicate_data["email"] = f"different_{test_user_data['email']}"
        
        response = client.post("/users/register", json=duplicate_data)
        
        assert response.status_code == 409, \
            f"Expected 409 for duplicate username, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data, "conflict")
        assert "username" in error_data["error_description"].lower()
    
    def test_user_registration_duplicate_email(self, client, test_user_data):
        """Test user registration with duplicate email."""
        # Register first user
        response = client.post("/users/register", json=test_user_data)
        assert response.status_code == 201, "First registration failed"
        
        # Try to register with same email but different username
        duplicate_data = test_user_data.copy()
        duplicate_data["username"] = f"different_{test_user_data['username']}"
        
        response = client.post("/users/register", json=duplicate_data)
        
        assert response.status_code == 409, \
            f"Expected 409 for duplicate email, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data, "conflict")
        assert "email" in error_data["error_description"].lower()
    
    def test_user_registration_invalid_data(self, client):
        """Test user registration with invalid data."""
        # Missing required fields
        invalid_data = {
            "username": "testuser",
            # Missing email and password
        }
        
        response = client.post("/users/register", json=invalid_data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for invalid data, got {response.status_code}"
        
        # Invalid email format
        invalid_data = {
            "username": "testuser",
            "email": "invalid-email",
            "password": "TestPass123!"
        }
        
        response = client.post("/users/register", json=invalid_data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for invalid email, got {response.status_code}"
        
        # Weak password
        invalid_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "weak"
        }
        
        response = client.post("/users/register", json=invalid_data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for weak password, got {response.status_code}"
    
    def test_get_current_user_profile(self, user_client):
        """Test getting current user profile."""
        response = user_client.get("/users/me")
        
        assert response.status_code == 200, \
            f"Get profile failed: {response.status_code} - {response.text}"
        
        profile_data = response.json()
        assert_valid_user_response(profile_data, USER_USERNAME)
        
        # Verify profile contains expected fields
        assert "roles" in profile_data, "Roles not in profile"
        assert "created_at" in profile_data, "Created timestamp not in profile"
        assert "updated_at" in profile_data, "Updated timestamp not in profile"
    
    def test_get_user_profile_alias(self, user_client):
        """Test getting user profile via /profile alias."""
        response = user_client.get("/users/profile")
        
        assert response.status_code == 200, \
            f"Get profile alias failed: {response.status_code} - {response.text}"
        
        profile_data = response.json()
        assert_valid_user_response(profile_data, USER_USERNAME)
    
    def test_get_current_user_profile_unauthenticated(self, client):
        """Test getting current user profile without authentication."""
        response = client.get("/users/me")
        
        assert response.status_code == 401, \
            f"Expected 401 for unauthenticated request, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
    
    def test_update_current_user_profile(self, user_client):
        """Test updating current user profile."""
        # Get original profile
        response = user_client.get("/users/me")
        assert response.status_code == 200, "Failed to get original profile"
        original_profile = response.json()
        
        # Update profile
        update_data = {
            "first_name": "Updated",
            "last_name": "Name",
            "display_name": "Updated Display Name",
            "bio": "Updated bio for testing"
        }
        
        response = user_client.put("/users/me", json=update_data)
        
        assert response.status_code == 200, \
            f"Profile update failed: {response.status_code} - {response.text}"
        
        updated_profile = response.json()
        assert_valid_user_response(updated_profile, USER_USERNAME)
        
        # Verify updates were applied
        assert updated_profile["first_name"] == update_data["first_name"]
        assert updated_profile["last_name"] == update_data["last_name"]
        assert updated_profile["display_name"] == update_data["display_name"]
        assert updated_profile["bio"] == update_data["bio"]
        
        # Verify unchanged fields remain the same
        assert updated_profile["username"] == original_profile["username"]
        assert updated_profile["email"] == original_profile["email"]
        assert updated_profile["id"] == original_profile["id"]
    
    def test_update_current_user_email(self, user_client):
        """Test updating current user email."""
        # Generate unique email
        unique_id = str(uuid.uuid4())[:8]
        new_email = f"updated_{unique_id}@permiso.test"
        
        update_data = {"email": new_email}
        
        response = user_client.put("/users/me", json=update_data)
        
        assert response.status_code == 200, \
            f"Email update failed: {response.status_code} - {response.text}"
        
        updated_profile = response.json()
        assert updated_profile["email"] == new_email
        
        # Email change should reset verification status
        assert updated_profile.get("is_verified", True) is False
    
    def test_update_current_user_profile_invalid_data(self, user_client):
        """Test updating profile with invalid data."""
        # Try to update username (should not be allowed)
        update_data = {"username": "new_username"}
        
        response = user_client.put("/users/me", json=update_data)
        # This might be allowed or rejected depending on implementation
        # If rejected, should be 400/422, if allowed, username should remain unchanged
        
        if response.status_code in [400, 422]:
            error_data = response.json()
            assert_error_response(error_data)
        else:
            # If update was accepted, verify username didn't actually change
            profile = response.json()
            assert profile["username"] == USER_USERNAME
    
    def test_admin_create_user(self, admin_client, test_user_data):
        """Test admin creating a new user."""
        response = admin_client.post("/users", json=test_user_data)
        
        assert response.status_code == 201, \
            f"Admin user creation failed: {response.status_code} - {response.text}"
        
        created_user = response.json()
        assert_valid_user_response(created_user, test_user_data["username"])
        
        # Verify all data was set correctly
        assert created_user["email"] == test_user_data["email"]
        assert created_user["first_name"] == test_user_data["first_name"]
        assert created_user["last_name"] == test_user_data["last_name"]
        
        return created_user["id"]
    
    def test_admin_get_user_by_id(self, admin_client, test_user_data):
        """Test admin getting user by ID."""
        # First create a user
        response = admin_client.post("/users", json=test_user_data)
        assert response.status_code == 201, "User creation failed"
        created_user = response.json()
        user_id = created_user["id"]
        
        # Get user by ID
        response = admin_client.get(f"/users/{user_id}")
        
        assert response.status_code == 200, \
            f"Get user by ID failed: {response.status_code} - {response.text}"
        
        user_data = response.json()
        assert_valid_user_response(user_data, test_user_data["username"])
        assert user_data["id"] == user_id
    
    def test_admin_get_nonexistent_user(self, admin_client):
        """Test admin getting non-existent user."""
        fake_id = str(uuid.uuid4())
        
        response = admin_client.get(f"/users/{fake_id}")
        
        assert response.status_code == 404, \
            f"Expected 404 for non-existent user, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
    
    def test_admin_update_user(self, admin_client, test_user_data):
        """Test admin updating a user."""
        # First create a user
        response = admin_client.post("/users", json=test_user_data)
        assert response.status_code == 201, "User creation failed"
        created_user = response.json()
        user_id = created_user["id"]
        
        # Update user
        update_data = {
            "first_name": "Admin Updated",
            "last_name": "Name",
            "is_active": False,
            "is_verified": True
        }
        
        response = admin_client.put(f"/users/{user_id}", json=update_data)
        
        assert response.status_code == 200, \
            f"Admin user update failed: {response.status_code} - {response.text}"
        
        updated_user = response.json()
        assert_valid_user_response(updated_user, test_user_data["username"])
        
        # Verify updates were applied
        assert updated_user["first_name"] == update_data["first_name"]
        assert updated_user["last_name"] == update_data["last_name"]
        assert updated_user["is_active"] == update_data["is_active"]
        assert updated_user["is_verified"] == update_data["is_verified"]
    
    def test_admin_delete_user(self, admin_client, test_user_data):
        """Test admin deleting a user."""
        # First create a user
        response = admin_client.post("/users", json=test_user_data)
        assert response.status_code == 201, "User creation failed"
        created_user = response.json()
        user_id = created_user["id"]
        
        # Delete user
        response = admin_client.delete(f"/users/{user_id}")
        
        assert response.status_code == 204, \
            f"Admin user deletion failed: {response.status_code} - {response.text}"
        
        # Verify user is deleted
        response = admin_client.get(f"/users/{user_id}")
        assert response.status_code == 404, \
            "User still exists after deletion"
    
    def test_admin_list_users(self, admin_client):
        """Test admin listing users."""
        response = admin_client.get("/users")
        
        assert response.status_code == 200, \
            f"List users failed: {response.status_code} - {response.text}"
        
        users_data = response.json()
        assert "users" in users_data, "Users list not in response"
        assert "total" in users_data, "Total count not in response"
        assert "page" in users_data, "Page number not in response"
        assert "per_page" in users_data, "Per page count not in response"
        
        # Verify users list structure
        users_list = users_data["users"]
        assert isinstance(users_list, list), "Users should be a list"
        
        if users_list:  # If there are users
            for user in users_list:
                assert_valid_user_response(user)
    
    def test_admin_list_users_with_pagination(self, admin_client):
        """Test admin listing users with pagination."""
        # Test with specific page and per_page
        response = admin_client.get("/users?page=1&per_page=5")
        
        assert response.status_code == 200, \
            f"List users with pagination failed: {response.status_code} - {response.text}"
        
        users_data = response.json()
        assert users_data["page"] == 1
        assert users_data["per_page"] == 5
        assert len(users_data["users"]) <= 5
    
    def test_admin_list_users_with_search(self, admin_client, test_user_data):
        """Test admin listing users with search."""
        # First create a user to search for
        response = admin_client.post("/users", json=test_user_data)
        assert response.status_code == 201, "User creation failed"
        
        # Search for the user
        search_term = test_user_data["username"][:5]  # Use partial username
        response = admin_client.get(f"/users?search={search_term}")
        
        assert response.status_code == 200, \
            f"Search users failed: {response.status_code} - {response.text}"
        
        users_data = response.json()
        users_list = users_data["users"]
        
        # Should find at least the user we created
        found_user = False
        for user in users_list:
            if user["username"] == test_user_data["username"]:
                found_user = True
                break
        
        assert found_user, f"Created user not found in search results for '{search_term}'"
    
    def test_user_statistics(self, admin_client):
        """Test user statistics endpoint."""
        response = admin_client.get("/users/stats/overview")
        
        assert response.status_code == 200, \
            f"User stats failed: {response.status_code} - {response.text}"
        
        stats_data = response.json()
        
        # Verify required statistics fields
        required_fields = ["total_users", "active_users", "verified_users"]
        for field in required_fields:
            assert field in stats_data, f"{field} not in statistics"
            assert isinstance(stats_data[field], int), f"{field} should be integer"
            assert stats_data[field] >= 0, f"{field} should be non-negative"
        
        # Logical consistency checks
        assert stats_data["active_users"] <= stats_data["total_users"], \
            "Active users cannot exceed total users"
        assert stats_data["verified_users"] <= stats_data["total_users"], \
            "Verified users cannot exceed total users"
    
    def test_user_password_update(self, user_client):
        """Test user password update."""
        # Update password
        password_data = {
            "current_password": USER_PASSWORD,
            "new_password": "NewTestPass123!"
        }
        
        # Get user ID first
        response = user_client.get("/users/me")
        assert response.status_code == 200, "Failed to get user profile"
        user_profile = response.json()
        user_id = user_profile["id"]
        
        response = user_client.put(f"/users/{user_id}/password", json=password_data)
        
        assert response.status_code == 200, \
            f"Password update failed: {response.status_code} - {response.text}"
        
        result = response.json()
        assert "message" in result, "Success message not returned"
        
        # Verify old password no longer works
        test_client = PermisoClient()
        old_login_success = test_client.login_user(USER_USERNAME, USER_PASSWORD)
        assert not old_login_success, "Old password still works"
        
        # Verify new password works
        new_login_success = test_client.login_user(USER_USERNAME, password_data["new_password"])
        assert new_login_success, "New password doesn't work"
        
        # Reset password back for other tests
        reset_data = {
            "current_password": password_data["new_password"],
            "new_password": USER_PASSWORD
        }
        
        authenticated_client = PermisoClient()
        authenticated_client.login_user(USER_USERNAME, password_data["new_password"])
        response = authenticated_client.put(f"/users/{user_id}/password", json=reset_data)
        assert response.status_code == 200, "Failed to reset password"
    
    def test_user_password_update_wrong_current_password(self, user_client):
        """Test user password update with wrong current password."""
        # Get user ID first
        response = user_client.get("/users/me")
        assert response.status_code == 200, "Failed to get user profile"
        user_profile = response.json()
        user_id = user_profile["id"]
        
        # Try to update with wrong current password
        password_data = {
            "current_password": "WrongPassword123!",
            "new_password": "NewTestPass123!"
        }
        
        response = user_client.put(f"/users/{user_id}/password", json=password_data)
        
        assert response.status_code == 400, \
            f"Expected 400 for wrong current password, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
        assert "current password" in error_data["error_description"].lower()
    
    def test_non_admin_cannot_access_other_users(self, user_client):
        """Test that non-admin users cannot access other users' data."""
        # Try to access admin user data (assuming admin has a different ID)
        fake_user_id = str(uuid.uuid4())
        
        response = user_client.get(f"/users/{fake_user_id}")
        
        assert response.status_code in [403, 404], \
            f"Expected 403/404 for unauthorized access, got {response.status_code}"
    
    def test_non_admin_cannot_create_users(self, user_client, test_user_data):
        """Test that non-admin users cannot create users via admin endpoint."""
        response = user_client.post("/users", json=test_user_data)
        
        assert response.status_code == 403, \
            f"Expected 403 for non-admin user creation, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)