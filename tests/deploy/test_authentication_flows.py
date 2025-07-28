"""Authentication flow functional tests."""

import pytest
import time
from conftest import (
    PermisoClient, 
    ADMIN_USERNAME, 
    ADMIN_PASSWORD, 
    USER_USERNAME, 
    USER_PASSWORD,
    CLIENT_ID,
    CLIENT_SECRET,
    assert_valid_token_response,
    assert_error_response
)


class TestAuthenticationFlows:
    """Test authentication flows and token management."""
    
    def test_user_login_success(self, client):
        """Test successful user login with valid credentials."""
        data = {
            "username": USER_USERNAME,
            "password": USER_PASSWORD,
            "grant_type": "password"
        }
        
        response = client.post("/auth/token", data=data)
        
        assert response.status_code == 200, \
            f"Login failed: {response.status_code} - {response.text}"
        
        token_data = response.json()
        assert_valid_token_response(token_data)
        
        # Verify refresh token is included for user login
        assert "refresh_token" in token_data, "Refresh token not returned for user login"
        assert "scope" in token_data, "Scope not returned in token response"
    
    def test_user_login_invalid_credentials(self, client):
        """Test login with invalid credentials returns proper error."""
        data = {
            "username": "invalid_user",
            "password": "wrong_password",
            "grant_type": "password"
        }
        
        response = client.post("/auth/token", data=data)
        
        assert response.status_code == 401, \
            f"Expected 401 for invalid credentials, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
        assert error_data["error"] in ["invalid_grant", "authentication_error"], \
            f"Unexpected error type: {error_data['error']}"
    
    def test_user_login_missing_fields(self, client):
        """Test login with missing required fields."""
        # Missing password
        data = {
            "username": USER_USERNAME,
            "grant_type": "password"
        }
        
        response = client.post("/auth/token", data=data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for missing password, got {response.status_code}"
        
        # Missing username
        data = {
            "password": USER_PASSWORD,
            "grant_type": "password"
        }
        
        response = client.post("/auth/token", data=data)
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for missing username, got {response.status_code}"
    
    def test_service_client_authentication_success(self, client):
        """Test successful service client authentication."""
        data = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "client_credentials"
        }
        
        response = client.post("/auth/service-token", data=data)
        
        assert response.status_code == 200, \
            f"Service client auth failed: {response.status_code} - {response.text}"
        
        token_data = response.json()
        assert_valid_token_response(token_data)
        
        # Service tokens typically don't include refresh tokens
        assert "scope" in token_data, "Scope not returned in service token response"
    
    def test_service_client_invalid_credentials(self, client):
        """Test service client authentication with invalid credentials."""
        data = {
            "client_id": "invalid_client",
            "client_secret": "invalid_secret",
            "grant_type": "client_credentials"
        }
        
        response = client.post("/auth/service-token", data=data)
        
        assert response.status_code == 401, \
            f"Expected 401 for invalid client credentials, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
        assert error_data["error"] in ["invalid_client", "authentication_error"], \
            f"Unexpected error type: {error_data['error']}"
    
    def test_token_refresh_success(self, client):
        """Test successful token refresh."""
        # First login to get tokens
        success = client.login_user(USER_USERNAME, USER_PASSWORD)
        assert success, "Initial login failed"
        
        original_token = client.access_token
        refresh_token = client.refresh_token
        assert refresh_token, "No refresh token available"
        
        # Wait a moment to ensure new token will be different
        time.sleep(1)
        
        # Refresh token
        data = {"refresh_token": refresh_token}
        response = client.post("/auth/refresh", json=data)
        
        assert response.status_code == 200, \
            f"Token refresh failed: {response.status_code} - {response.text}"
        
        new_token_data = response.json()
        assert_valid_token_response(new_token_data)
        
        # Verify new token is different
        new_access_token = new_token_data["access_token"]
        assert new_access_token != original_token, \
            "New access token same as original"
        
        # Verify new refresh token is provided
        assert "refresh_token" in new_token_data, "New refresh token not provided"
        new_refresh_token = new_token_data["refresh_token"]
        assert new_refresh_token != refresh_token, \
            "New refresh token same as original"
    
    def test_token_refresh_invalid_token(self, client):
        """Test token refresh with invalid refresh token."""
        data = {"refresh_token": "invalid_refresh_token"}
        response = client.post("/auth/refresh", json=data)
        
        assert response.status_code == 401, \
            f"Expected 401 for invalid refresh token, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
        assert error_data["error"] == "invalid_grant", \
            f"Expected invalid_grant error, got {error_data['error']}"
    
    def test_token_refresh_expired_token(self, client):
        """Test token refresh with expired refresh token."""
        # Use a clearly expired token (this is a mock expired token)
        expired_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.invalid"
        
        data = {"refresh_token": expired_token}
        response = client.post("/auth/refresh", json=data)
        
        assert response.status_code == 401, \
            f"Expected 401 for expired refresh token, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
    
    def test_authenticated_request_with_valid_token(self, user_client):
        """Test making authenticated request with valid token."""
        response = user_client.get("/users/me")
        
        assert response.status_code == 200, \
            f"Authenticated request failed: {response.status_code} - {response.text}"
        
        user_data = response.json()
        assert user_data["username"] == USER_USERNAME, \
            f"Username mismatch: expected {USER_USERNAME}, got {user_data['username']}"
    
    def test_authenticated_request_without_token(self, client):
        """Test making authenticated request without token."""
        response = client.get("/users/me")
        
        assert response.status_code == 401, \
            f"Expected 401 for unauthenticated request, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
    
    def test_authenticated_request_with_invalid_token(self, client):
        """Test making authenticated request with invalid token."""
        # Set invalid token
        client.access_token = "invalid_token"
        client.session.headers['Authorization'] = "Bearer invalid_token"
        
        response = client.get("/users/me")
        
        assert response.status_code == 401, \
            f"Expected 401 for invalid token, got {response.status_code}"
        
        error_data = response.json()
        assert_error_response(error_data)
    
    def test_logout_success(self, user_client):
        """Test successful user logout."""
        # Verify we can access protected endpoint before logout
        response = user_client.get("/users/me")
        assert response.status_code == 200, "Initial auth check failed"
        
        # Logout
        response = user_client.post("/auth/logout")
        assert response.status_code == 200, \
            f"Logout failed: {response.status_code} - {response.text}"
        
        logout_data = response.json()
        assert "message" in logout_data, "Logout message not returned"
        assert "sessions_terminated" in logout_data, "Sessions terminated count not returned"
        
        # Verify token is revoked - should get 401 now
        response = user_client.get("/users/me")
        assert response.status_code == 401, \
            "Token not properly revoked after logout"
    
    def test_logout_without_authentication(self, client):
        """Test logout without being authenticated."""
        response = client.post("/auth/logout")
        
        # Should return 401 since no authentication provided
        assert response.status_code == 401, \
            f"Expected 401 for unauthenticated logout, got {response.status_code}"
    
    def test_multiple_login_sessions(self, client):
        """Test that multiple login sessions can coexist."""
        # Create first session
        client1 = PermisoClient()
        success1 = client1.login_user(USER_USERNAME, USER_PASSWORD)
        assert success1, "First login failed"
        
        # Create second session
        client2 = PermisoClient()
        success2 = client2.login_user(USER_USERNAME, USER_PASSWORD)
        assert success2, "Second login failed"
        
        # Both sessions should work
        response1 = client1.get("/users/me")
        assert response1.status_code == 200, "First session not working"
        
        response2 = client2.get("/users/me")
        assert response2.status_code == 200, "Second session not working"
        
        # Logout first session
        client1.logout()
        
        # First session should be invalid
        response1 = client1.get("/users/me")
        assert response1.status_code == 401, "First session not properly logged out"
        
        # Second session should still work
        response2 = client2.get("/users/me")
        assert response2.status_code == 200, "Second session affected by first logout"
        
        # Cleanup
        client2.logout()
    
    def test_token_introspection(self, admin_client, user_client):
        """Test token introspection endpoint."""
        # Get a valid user token
        user_token = user_client.access_token
        assert user_token, "No user token available"
        
        # Introspect the token using admin client
        data = {"token": user_token}
        response = admin_client.post("/auth/introspect", json=data)
        
        assert response.status_code == 200, \
            f"Token introspection failed: {response.status_code} - {response.text}"
        
        introspection_data = response.json()
        assert "active" in introspection_data, "Active field not in introspection response"
        assert introspection_data["active"] is True, "Token should be active"
        assert "sub" in introspection_data, "Subject not in introspection response"
        assert "username" in introspection_data, "Username not in introspection response"
        assert "exp" in introspection_data, "Expiry not in introspection response"
    
    def test_token_revocation(self, admin_client, user_client):
        """Test token revocation endpoint."""
        # Get a valid user token
        user_token = user_client.access_token
        assert user_token, "No user token available"
        
        # Verify token works before revocation
        response = user_client.get("/users/me")
        assert response.status_code == 200, "Token should work before revocation"
        
        # Revoke the token using admin client
        data = {"token": user_token}
        response = admin_client.post("/auth/revoke", json=data)
        
        assert response.status_code == 200, \
            f"Token revocation failed: {response.status_code} - {response.text}"
        
        revocation_data = response.json()
        assert "message" in revocation_data, "Revocation message not returned"
        
        # Verify token is revoked - should get 401 now
        response = user_client.get("/users/me")
        assert response.status_code == 401, \
            "Token not properly revoked"
    
    def test_complete_authentication_flow(self, client):
        """Test complete authentication flow from login to logout."""
        # Step 1: Login
        success = client.login_user(USER_USERNAME, USER_PASSWORD)
        assert success, "Login failed"
        
        # Step 2: Use token for authenticated request
        response = client.get("/users/me")
        assert response.status_code == 200, "Authenticated request failed"
        user_data = response.json()
        assert user_data["username"] == USER_USERNAME, "User data mismatch"
        
        # Step 3: Refresh token
        original_token = client.access_token
        success = client.refresh_access_token()
        assert success, "Token refresh failed"
        assert client.access_token != original_token, "Token not refreshed"
        
        # Step 4: Use refreshed token
        response = client.get("/users/me")
        assert response.status_code == 200, "Refreshed token not working"
        
        # Step 5: Logout
        response = client.post("/auth/logout")
        assert response.status_code == 200, "Logout failed"
        
        # Step 6: Verify token is revoked
        response = client.get("/users/me")
        assert response.status_code == 401, "Token not revoked after logout"