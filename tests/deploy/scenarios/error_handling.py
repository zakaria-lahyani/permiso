"""Error handling test scenarios for Permiso functional testing."""

import pytest
import uuid
from conftest import (
    PermisoClient,
    USER_USERNAME,
    USER_PASSWORD,
    assert_error_response
)


class TestErrorHandlingScenarios:
    """Test error scenarios and proper error response handling."""
    
    def test_authentication_errors_comprehensive(self, client):
        """Test comprehensive authentication error scenarios."""
        # Scenario 1: Invalid credentials
        data = {
            "username": "nonexistent_user",
            "password": "wrong_password",
            "grant_type": "password"
        }
        
        response = client.post("/auth/token", data=data)
        assert response.status_code == 401, \
            f"Expected 401 for invalid credentials, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
        assert error_data["error"] in ["invalid_grant", "authentication_error"]
        
        # Scenario 2: Missing username
        data = {
            "password": USER_PASSWORD,
            "grant_type": "password"
        }
        
        response = client.post("/auth/token", data=data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for missing username, got {response.status_code}"
        
        # Scenario 3: Missing password
        data = {
            "username": USER_USERNAME,
            "grant_type": "password"
        }
        
        response = client.post("/auth/token", data=data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for missing password, got {response.status_code}"
        
        # Scenario 4: Invalid grant type
        data = {
            "username": USER_USERNAME,
            "password": USER_PASSWORD,
            "grant_type": "invalid_grant"
        }
        
        response = client.post("/auth/token", data=data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for invalid grant type, got {response.status_code}"
        
        # Scenario 5: Empty credentials
        data = {
            "username": "",
            "password": "",
            "grant_type": "password"
        }
        
        response = client.post("/auth/token", data=data)
        assert response.status_code in [400, 401, 422], \
            f"Expected 400/401/422 for empty credentials, got {response.status_code}"
    
    def test_token_refresh_errors(self, client):
        """Test token refresh error scenarios."""
        # Scenario 1: Invalid refresh token
        data = {"refresh_token": "invalid_token_string"}
        response = client.post("/auth/refresh", json=data)
        
        assert response.status_code == 401, \
            f"Expected 401 for invalid refresh token, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data, "invalid_grant")
        
        # Scenario 2: Malformed refresh token
        data = {"refresh_token": "malformed.token.here"}
        response = client.post("/auth/refresh", json=data)
        
        assert response.status_code == 401, \
            f"Expected 401 for malformed refresh token, got {response.status_code}"
        
        # Scenario 3: Missing refresh token
        data = {}
        response = client.post("/auth/refresh", json=data)
        
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for missing refresh token, got {response.status_code}"
        
        # Scenario 4: Empty refresh token
        data = {"refresh_token": ""}
        response = client.post("/auth/refresh", json=data)
        
        assert response.status_code in [400, 401, 422], \
            f"Expected 400/401/422 for empty refresh token, got {response.status_code}"
        
        # Scenario 5: Wrong field name
        data = {"token": "some_token_value"}  # Should be "refresh_token"
        response = client.post("/auth/refresh", json=data)
        
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for wrong field name, got {response.status_code}"
    
    def test_unauthorized_access_errors(self, client):
        """Test unauthorized access error scenarios."""
        # Scenario 1: Access protected endpoint without token
        response = client.get("/users/me")
        assert response.status_code == 401, \
            f"Expected 401 for no token, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
        
        # Scenario 2: Access with invalid token
        client.session.headers['Authorization'] = "Bearer invalid_token"
        response = client.get("/users/me")
        assert response.status_code == 401, \
            f"Expected 401 for invalid token, got {response.status_code}"
        
        # Scenario 3: Access with malformed authorization header
        client.session.headers['Authorization'] = "InvalidFormat token_here"
        response = client.get("/users/me")
        assert response.status_code == 401, \
            f"Expected 401 for malformed auth header, got {response.status_code}"
        
        # Scenario 4: Access with empty authorization header
        client.session.headers['Authorization'] = ""
        response = client.get("/users/me")
        assert response.status_code == 401, \
            f"Expected 401 for empty auth header, got {response.status_code}"
        
        # Clean up headers
        if 'Authorization' in client.session.headers:
            del client.session.headers['Authorization']
    
    def test_user_registration_errors(self, client):
        """Test user registration error scenarios."""
        # Scenario 1: Missing required fields
        incomplete_data = {
            "username": "testuser"
            # Missing email and password
        }
        
        response = client.post("/users/register", json=incomplete_data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for incomplete data, got {response.status_code}"
        
        # Scenario 2: Invalid email format
        invalid_email_data = {
            "username": f"testuser_{uuid.uuid4().hex[:8]}",
            "email": "invalid-email-format",
            "password": "TestPass123!"
        }
        
        response = client.post("/users/register", json=invalid_email_data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for invalid email, got {response.status_code}"
        
        # Scenario 3: Weak password
        weak_password_data = {
            "username": f"testuser_{uuid.uuid4().hex[:8]}",
            "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
            "password": "weak"
        }
        
        response = client.post("/users/register", json=weak_password_data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for weak password, got {response.status_code}"
        
        # Scenario 4: Username too short
        short_username_data = {
            "username": "ab",  # Too short
            "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
            "password": "TestPass123!"
        }
        
        response = client.post("/users/register", json=short_username_data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for short username, got {response.status_code}"
        
        # Scenario 5: Invalid JSON payload
        response = client.session.post(
            f"{client.base_url}{client.api_base}/users/register",
            data="invalid json data",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for invalid JSON, got {response.status_code}"
    
    def test_user_profile_update_errors(self, user_client):
        """Test user profile update error scenarios."""
        # Scenario 1: Invalid email format
        invalid_data = {"email": "invalid-email-format"}
        response = user_client.put("/users/me", json=invalid_data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for invalid email, got {response.status_code}"
        
        # Scenario 2: Extremely long field values
        long_data = {
            "first_name": "a" * 1000,  # Extremely long name
            "bio": "b" * 10000  # Extremely long bio
        }
        response = user_client.put("/users/me", json=long_data)
        # This might be accepted or rejected depending on validation rules
        assert response.status_code in [200, 400, 422], \
            f"Unexpected status for long field values: {response.status_code}"
        
        # Scenario 3: Invalid field types
        invalid_type_data = {
            "first_name": 12345,  # Should be string
            "is_active": "not_boolean"  # Should be boolean
        }
        response = user_client.put("/users/me", json=invalid_type_data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for invalid field types, got {response.status_code}"
        
        # Scenario 4: Null values for required fields
        null_data = {
            "email": None,
            "first_name": None
        }
        response = user_client.put("/users/me", json=null_data)
        # Behavior depends on whether these fields are required
        assert response.status_code in [200, 400, 422], \
            f"Unexpected status for null values: {response.status_code}"
    
    def test_password_change_errors(self, user_client):
        """Test password change error scenarios."""
        # Get user ID first
        response = user_client.get("/users/me")
        assert response.status_code == 200, "Failed to get user profile"
        user_profile = response.json()
        user_id = user_profile["id"]
        
        # Scenario 1: Wrong current password
        wrong_password_data = {
            "current_password": "WrongPassword123!",
            "new_password": "NewTestPass123!"
        }
        
        response = user_client.put(f"/users/{user_id}/password", json=wrong_password_data)
        assert response.status_code == 400, \
            f"Expected 400 for wrong current password, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
        assert "current password" in error_data["error_description"].lower()
        
        # Scenario 2: Weak new password
        weak_password_data = {
            "current_password": USER_PASSWORD,
            "new_password": "weak"
        }
        
        response = user_client.put(f"/users/{user_id}/password", json=weak_password_data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for weak new password, got {response.status_code}"
        
        # Scenario 3: Missing current password
        missing_current_data = {
            "new_password": "NewTestPass123!"
        }
        
        response = user_client.put(f"/users/{user_id}/password", json=missing_current_data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for missing current password, got {response.status_code}"
        
        # Scenario 4: Missing new password
        missing_new_data = {
            "current_password": USER_PASSWORD
        }
        
        response = user_client.put(f"/users/{user_id}/password", json=missing_new_data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for missing new password, got {response.status_code}"
        
        # Scenario 5: Same current and new password
        same_password_data = {
            "current_password": USER_PASSWORD,
            "new_password": USER_PASSWORD
        }
        
        response = user_client.put(f"/users/{user_id}/password", json=same_password_data)
        # This might be allowed or rejected depending on business rules
        assert response.status_code in [200, 400, 422], \
            f"Unexpected status for same password: {response.status_code}"
    
    def test_admin_access_errors(self, user_client):
        """Test admin access error scenarios with regular user."""
        # Scenario 1: Regular user trying to create users
        user_data = {
            "username": f"testuser_{uuid.uuid4().hex[:8]}",
            "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
            "password": "TestPass123!"
        }
        
        response = user_client.post("/users", json=user_data)
        assert response.status_code == 403, \
            f"Expected 403 for non-admin user creation, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
        
        # Scenario 2: Regular user trying to access user statistics
        response = user_client.get("/users/stats/overview")
        assert response.status_code == 403, \
            f"Expected 403 for non-admin stats access, got {response.status_code}"
        
        # Scenario 3: Regular user trying to access other user's data
        fake_user_id = str(uuid.uuid4())
        response = user_client.get(f"/users/{fake_user_id}")
        assert response.status_code in [403, 404], \
            f"Expected 403/404 for unauthorized user access, got {response.status_code}"
        
        # Scenario 4: Regular user trying to delete users
        response = user_client.delete(f"/users/{fake_user_id}")
        assert response.status_code in [403, 404], \
            f"Expected 403/404 for unauthorized user deletion, got {response.status_code}"
        
        # Scenario 5: Regular user trying to list all users
        response = user_client.get("/users")
        assert response.status_code == 403, \
            f"Expected 403 for non-admin user listing, got {response.status_code}"
    
    def test_resource_not_found_errors(self, admin_client):
        """Test resource not found error scenarios."""
        # Scenario 1: Non-existent user ID
        fake_user_id = str(uuid.uuid4())
        response = admin_client.get(f"/users/{fake_user_id}")
        assert response.status_code == 404, \
            f"Expected 404 for non-existent user, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
        
        # Scenario 2: Invalid user ID format
        invalid_id = "not-a-valid-uuid"
        response = admin_client.get(f"/users/{invalid_id}")
        assert response.status_code in [400, 404, 422], \
            f"Expected 400/404/422 for invalid user ID, got {response.status_code}"
        
        # Scenario 3: Non-existent endpoint
        response = admin_client.get("/users/nonexistent/endpoint")
        assert response.status_code == 404, \
            f"Expected 404 for non-existent endpoint, got {response.status_code}"
        
        # Scenario 4: Wrong HTTP method
        response = admin_client.patch("/users/me")  # PATCH might not be supported
        assert response.status_code in [404, 405], \
            f"Expected 404/405 for unsupported method, got {response.status_code}"
    
    def test_service_client_authentication_errors(self, client):
        """Test service client authentication error scenarios."""
        # Scenario 1: Invalid client credentials
        data = {
            "client_id": "invalid_client_id",
            "client_secret": "invalid_client_secret",
            "grant_type": "client_credentials"
        }
        
        response = client.post("/auth/service-token", data=data)
        assert response.status_code == 401, \
            f"Expected 401 for invalid client credentials, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
        assert error_data["error"] in ["invalid_client", "authentication_error"]
        
        # Scenario 2: Missing client ID
        data = {
            "client_secret": "some_secret",
            "grant_type": "client_credentials"
        }
        
        response = client.post("/auth/service-token", data=data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for missing client ID, got {response.status_code}"
        
        # Scenario 3: Missing client secret
        data = {
            "client_id": "some_client",
            "grant_type": "client_credentials"
        }
        
        response = client.post("/auth/service-token", data=data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for missing client secret, got {response.status_code}"
        
        # Scenario 4: Invalid grant type
        data = {
            "client_id": "some_client",
            "client_secret": "some_secret",
            "grant_type": "invalid_grant"
        }
        
        response = client.post("/auth/service-token", data=data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for invalid grant type, got {response.status_code}"
    
    def test_malformed_request_errors(self, client):
        """Test malformed request error scenarios."""
        # Scenario 1: Invalid JSON in request body
        response = client.session.post(
            f"{client.base_url}{client.api_base}/users/register",
            data="{ invalid json }",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for invalid JSON, got {response.status_code}"
        
        # Scenario 2: Wrong content type for JSON endpoint
        response = client.session.post(
            f"{client.base_url}{client.api_base}/users/register",
            data='{"username": "test"}',
            headers={"Content-Type": "text/plain"}
        )
        assert response.status_code in [400, 415, 422], \
            f"Expected 400/415/422 for wrong content type, got {response.status_code}"
        
        # Scenario 3: Extremely large request body
        large_data = {"bio": "x" * 1000000}  # 1MB of data
        response = client.post("/users/register", json=large_data)
        assert response.status_code in [400, 413, 422], \
            f"Expected 400/413/422 for large request, got {response.status_code}"
        
        # Scenario 4: Missing required headers
        response = client.session.post(
            f"{client.base_url}{client.api_base}/users/register",
            json={"username": "test"},
            headers={}  # No headers
        )
        # This might still work depending on server configuration
        assert response.status_code in [200, 201, 400, 415, 422], \
            f"Unexpected status for missing headers: {response.status_code}"
    
    def test_concurrent_operation_errors(self, client, test_user_data):
        """Test concurrent operation error scenarios."""
        # Scenario 1: Double registration with same username
        # First registration
        response1 = client.post("/users/register", json=test_user_data)
        assert response1.status_code == 201, "First registration should succeed"
        
        # Second registration with same data (should fail)
        response2 = client.post("/users/register", json=test_user_data)
        assert response2.status_code == 409, \
            f"Expected 409 for duplicate registration, got {response2.status_code}"
        
        error_data = response2.json()
        assert_error_response(error_data, "conflict")
        
        # Scenario 2: Multiple login attempts with same user
        client1 = PermisoClient()
        client2 = PermisoClient()
        
        success1 = client1.login_user(test_user_data["username"], test_user_data["password"])
        success2 = client2.login_user(test_user_data["username"], test_user_data["password"])
        
        # Both should succeed (multiple sessions allowed)
        assert success1, "First login should succeed"
        assert success2, "Second login should succeed"
        
        # Cleanup
        client1.logout()
        client2.logout()
    
    def test_session_management_errors(self, user_client):
        """Test session management error scenarios."""
        # Scenario 1: Access non-existent session
        fake_session_id = str(uuid.uuid4())
        response = user_client.post(f"/sessions/{fake_session_id}/renew")
        assert response.status_code in [404, 403], \
            f"Expected 404/403 for non-existent session, got {response.status_code}"
        
        # Scenario 2: Delete non-existent session
        response = user_client.delete(f"/sessions/{fake_session_id}")
        assert response.status_code in [404, 403], \
            f"Expected 404/403 for non-existent session deletion, got {response.status_code}"
        
        # Scenario 3: Invalid session ID format
        invalid_session_id = "not-a-valid-session-id"
        response = user_client.post(f"/sessions/{invalid_session_id}/renew")
        assert response.status_code in [400, 404, 422], \
            f"Expected 400/404/422 for invalid session ID, got {response.status_code}"
    
    def test_logout_errors(self, client):
        """Test logout error scenarios."""
        # Scenario 1: Logout without being authenticated
        response = client.post("/auth/logout")
        assert response.status_code == 401, \
            f"Expected 401 for unauthenticated logout, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
        
        # Scenario 2: Double logout
        # First login
        success = client.login_user(USER_USERNAME, USER_PASSWORD)
        assert success, "Login should succeed"
        
        # First logout
        response = client.post("/auth/logout")
        assert response.status_code == 200, "First logout should succeed"
        
        # Second logout (should fail)
        response = client.post("/auth/logout")
        assert response.status_code == 401, \
            f"Expected 401 for double logout, got {response.status_code}"