"""Happy path test scenarios for Permiso functional testing."""

import pytest
import uuid
from conftest import (
    PermisoClient,
    USER_USERNAME,
    USER_PASSWORD,
    CLIENT_ID,
    CLIENT_SECRET,
    assert_valid_user_response,
    assert_valid_token_response
)


class TestHappyPathScenarios:
    """Test standard successful workflows and user journeys."""
    
    def test_complete_user_registration_to_profile_journey(self, client):
        """Test complete user journey from registration to profile management."""
        # Step 1: Register new user
        unique_id = str(uuid.uuid4())[:8]
        user_data = {
            "username": f"journey_{unique_id}",
            "email": f"journey_{unique_id}@permiso.test",
            "password": "JourneyPass123!",
            "first_name": "Journey",
            "last_name": "User",
            "display_name": f"Journey User {unique_id}",
            "bio": "User created for journey testing"
        }
        
        response = client.post("/users/register", json=user_data)
        assert response.status_code == 201, \
            f"Step 1 - User registration failed: {response.status_code} - {response.text}"
        
        registered_user = response.json()
        assert_valid_user_response(registered_user, user_data["username"])
        
        # Step 2: Login with new user credentials
        login_success = client.login_user(user_data["username"], user_data["password"])
        assert login_success, "Step 2 - Login with new user failed"
        
        # Step 3: Get user profile to verify login worked
        response = client.get("/users/me")
        assert response.status_code == 200, \
            f"Step 3 - Get profile failed: {response.status_code} - {response.text}"
        
        profile = response.json()
        assert_valid_user_response(profile, user_data["username"])
        assert profile["email"] == user_data["email"]
        assert profile["first_name"] == user_data["first_name"]
        
        # Step 4: Update user profile
        update_data = {
            "bio": "Updated bio during journey test",
            "display_name": "Updated Journey User"
        }
        
        response = client.put("/users/me", json=update_data)
        assert response.status_code == 200, \
            f"Step 4 - Profile update failed: {response.status_code} - {response.text}"
        
        updated_profile = response.json()
        assert updated_profile["bio"] == update_data["bio"]
        assert updated_profile["display_name"] == update_data["display_name"]
        
        # Step 5: Verify profile update persisted
        response = client.get("/users/me")
        assert response.status_code == 200, \
            f"Step 5 - Profile verification failed: {response.status_code} - {response.text}"
        
        verified_profile = response.json()
        assert verified_profile["bio"] == update_data["bio"]
        assert verified_profile["display_name"] == update_data["display_name"]
        
        # Step 6: Test token refresh
        original_token = client.access_token
        refresh_success = client.refresh_access_token()
        assert refresh_success, "Step 6 - Token refresh failed"
        assert client.access_token != original_token, "Step 6 - Token not actually refreshed"
        
        # Step 7: Verify refreshed token works
        response = client.get("/users/me")
        assert response.status_code == 200, \
            f"Step 7 - Refreshed token test failed: {response.status_code} - {response.text}"
        
        # Step 8: Logout
        response = client.post("/auth/logout")
        assert response.status_code == 200, \
            f"Step 8 - Logout failed: {response.status_code} - {response.text}"
        
        # Step 9: Verify logout worked (token should be invalid)
        response = client.get("/users/me")
        assert response.status_code == 401, \
            "Step 9 - Token not properly revoked after logout"
    
    def test_admin_user_management_workflow(self, admin_client):
        """Test complete admin user management workflow."""
        # Step 1: Get initial user statistics
        response = admin_client.get("/users/stats/overview")
        assert response.status_code == 200, \
            f"Step 1 - Get user stats failed: {response.status_code} - {response.text}"
        
        initial_stats = response.json()
        initial_count = initial_stats["total_users"]
        
        # Step 2: Create new user via admin endpoint
        unique_id = str(uuid.uuid4())[:8]
        user_data = {
            "username": f"adminflow_{unique_id}",
            "email": f"adminflow_{unique_id}@permiso.test",
            "password": "AdminFlowPass123!",
            "first_name": "Admin",
            "last_name": "Flow",
            "display_name": f"Admin Flow User {unique_id}",
            "is_active": True,
            "is_verified": True
        }
        
        response = admin_client.post("/users", json=user_data)
        assert response.status_code == 201, \
            f"Step 2 - Admin user creation failed: {response.status_code} - {response.text}"
        
        created_user = response.json()
        user_id = created_user["id"]
        assert_valid_user_response(created_user, user_data["username"])
        
        # Step 3: Verify user count increased
        response = admin_client.get("/users/stats/overview")
        assert response.status_code == 200, \
            f"Step 3 - Get updated stats failed: {response.status_code} - {response.text}"
        
        updated_stats = response.json()
        assert updated_stats["total_users"] == initial_count + 1, \
            f"Step 3 - User count not updated: expected {initial_count + 1}, got {updated_stats['total_users']}"
        
        # Step 4: Get user by ID to verify creation
        response = admin_client.get(f"/users/{user_id}")
        assert response.status_code == 200, \
            f"Step 4 - Get user by ID failed: {response.status_code} - {response.text}"
        
        retrieved_user = response.json()
        assert retrieved_user["id"] == user_id
        assert retrieved_user["username"] == user_data["username"]
        
        # Step 5: Update user information
        update_data = {
            "first_name": "Updated Admin",
            "last_name": "Updated Flow",
            "bio": "Updated during admin workflow test",
            "is_active": True
        }
        
        response = admin_client.put(f"/users/{user_id}", json=update_data)
        assert response.status_code == 200, \
            f"Step 5 - User update failed: {response.status_code} - {response.text}"
        
        updated_user = response.json()
        assert updated_user["first_name"] == update_data["first_name"]
        assert updated_user["last_name"] == update_data["last_name"]
        assert updated_user["bio"] == update_data["bio"]
        
        # Step 6: Verify update persisted
        response = admin_client.get(f"/users/{user_id}")
        assert response.status_code == 200, \
            f"Step 6 - Get updated user failed: {response.status_code} - {response.text}"
        
        verified_user = response.json()
        assert verified_user["first_name"] == update_data["first_name"]
        assert verified_user["bio"] == update_data["bio"]
        
        # Step 7: List users and verify our user is included
        response = admin_client.get("/users")
        assert response.status_code == 200, \
            f"Step 7 - List users failed: {response.status_code} - {response.text}"
        
        users_list = response.json()
        found_user = False
        for user in users_list["users"]:
            if user["id"] == user_id:
                found_user = True
                break
        assert found_user, "Step 7 - Created user not found in users list"
        
        # Step 8: Search for the user
        search_term = user_data["username"][:5]
        response = admin_client.get(f"/users?search={search_term}")
        assert response.status_code == 200, \
            f"Step 8 - Search users failed: {response.status_code} - {response.text}"
        
        search_results = response.json()
        found_in_search = False
        for user in search_results["users"]:
            if user["id"] == user_id:
                found_in_search = True
                break
        assert found_in_search, "Step 8 - Created user not found in search results"
        
        # Step 9: Clean up - delete user
        response = admin_client.delete(f"/users/{user_id}")
        assert response.status_code == 204, \
            f"Step 9 - User deletion failed: {response.status_code} - {response.text}"
        
        # Step 10: Verify user is deleted
        response = admin_client.get(f"/users/{user_id}")
        assert response.status_code == 404, \
            "Step 10 - User still exists after deletion"
        
        # Step 11: Verify user count decreased
        response = admin_client.get("/users/stats/overview")
        assert response.status_code == 200, \
            f"Step 11 - Get final stats failed: {response.status_code} - {response.text}"
        
        final_stats = response.json()
        assert final_stats["total_users"] == initial_count, \
            f"Step 11 - User count not restored: expected {initial_count}, got {final_stats['total_users']}"
    
    def test_service_client_authentication_workflow(self, client):
        """Test service client authentication and API access workflow."""
        # Step 1: Authenticate as service client
        success = client.login_service_client(CLIENT_ID, CLIENT_SECRET)
        assert success, "Step 1 - Service client authentication failed"
        
        # Step 2: Verify we have a valid token
        assert client.access_token is not None, "Step 2 - No access token received"
        
        # Step 3: Test token introspection (if admin scope available)
        # Note: This might fail if service client doesn't have admin:tokens scope
        data = {"token": client.access_token}
        response = client.post("/auth/introspect", json=data)
        
        if response.status_code == 200:
            introspection_data = response.json()
            assert introspection_data["active"] is True, "Step 3 - Token should be active"
            assert "client_id" in introspection_data, "Step 3 - Client ID not in introspection"
        elif response.status_code == 403:
            # Service client doesn't have admin:tokens scope, which is expected
            pass
        else:
            pytest.fail(f"Step 3 - Unexpected introspection response: {response.status_code}")
        
        # Step 4: Try to access user endpoints (should work if service client has appropriate scopes)
        response = client.get("/users")
        
        if response.status_code == 200:
            # Service client has user read access
            users_data = response.json()
            assert "users" in users_data, "Step 4 - Users list not in response"
        elif response.status_code == 403:
            # Service client doesn't have user read access, which is acceptable
            pass
        else:
            pytest.fail(f"Step 4 - Unexpected users endpoint response: {response.status_code}")
        
        # Step 5: Test token revocation (if admin scope available)
        data = {"token": client.access_token}
        response = client.post("/auth/revoke", json=data)
        
        if response.status_code == 200:
            # Token was successfully revoked
            revocation_data = response.json()
            assert "message" in revocation_data, "Step 5 - Revocation message not returned"
            
            # Step 6: Verify token is revoked
            response = client.get("/users")
            assert response.status_code == 401, "Step 6 - Token not properly revoked"
        elif response.status_code == 403:
            # Service client doesn't have admin:tokens scope for revocation
            pass
        else:
            pytest.fail(f"Step 5 - Unexpected revocation response: {response.status_code}")
    
    def test_multi_user_session_management(self, client):
        """Test managing multiple user sessions."""
        # Step 1: Create first user session
        client1 = PermisoClient()
        success1 = client1.login_user(USER_USERNAME, USER_PASSWORD)
        assert success1, "Step 1 - First user login failed"
        
        # Step 2: Create second user session (same user, different session)
        client2 = PermisoClient()
        success2 = client2.login_user(USER_USERNAME, USER_PASSWORD)
        assert success2, "Step 2 - Second user login failed"
        
        # Step 3: Verify both sessions work independently
        response1 = client1.get("/users/me")
        assert response1.status_code == 200, "Step 3 - First session not working"
        
        response2 = client2.get("/users/me")
        assert response2.status_code == 200, "Step 3 - Second session not working"
        
        # Step 4: Get session list from first client
        response = client1.get("/sessions")
        if response.status_code == 200:
            sessions_data = response.json()
            assert "sessions" in sessions_data, "Step 4 - Sessions list not in response"
            assert len(sessions_data["sessions"]) >= 2, "Step 4 - Not enough sessions found"
        
        # Step 5: Logout first session
        response = client1.post("/auth/logout")
        assert response.status_code == 200, "Step 5 - First session logout failed"
        
        # Step 6: Verify first session is invalid
        response1 = client1.get("/users/me")
        assert response1.status_code == 401, "Step 6 - First session not properly logged out"
        
        # Step 7: Verify second session still works
        response2 = client2.get("/users/me")
        assert response2.status_code == 200, "Step 7 - Second session affected by first logout"
        
        # Step 8: Cleanup - logout second session
        client2.logout()
    
    def test_password_change_workflow(self, user_client):
        """Test complete password change workflow."""
        # Step 1: Get user profile to get user ID
        response = user_client.get("/users/me")
        assert response.status_code == 200, "Step 1 - Get user profile failed"
        user_profile = response.json()
        user_id = user_profile["id"]
        
        # Step 2: Change password
        new_password = "NewTestPassword123!"
        password_data = {
            "current_password": USER_PASSWORD,
            "new_password": new_password
        }
        
        response = user_client.put(f"/users/{user_id}/password", json=password_data)
        assert response.status_code == 200, \
            f"Step 2 - Password change failed: {response.status_code} - {response.text}"
        
        # Step 3: Verify old password no longer works
        test_client = PermisoClient()
        old_login_success = test_client.login_user(USER_USERNAME, USER_PASSWORD)
        assert not old_login_success, "Step 3 - Old password still works"
        
        # Step 4: Verify new password works
        new_login_success = test_client.login_user(USER_USERNAME, new_password)
        assert new_login_success, "Step 4 - New password doesn't work"
        
        # Step 5: Login with new password and verify profile access
        response = test_client.get("/users/me")
        assert response.status_code == 200, "Step 5 - Profile access with new password failed"
        
        profile_data = response.json()
        assert profile_data["username"] == USER_USERNAME, "Step 5 - Profile data mismatch"
        
        # Step 6: Reset password back to original for other tests
        reset_data = {
            "current_password": new_password,
            "new_password": USER_PASSWORD
        }
        
        response = test_client.put(f"/users/{user_id}/password", json=reset_data)
        assert response.status_code == 200, "Step 6 - Password reset failed"
        
        # Step 7: Verify original password works again
        final_client = PermisoClient()
        final_login_success = final_client.login_user(USER_USERNAME, USER_PASSWORD)
        assert final_login_success, "Step 7 - Original password not restored"
        
        # Cleanup
        test_client.logout()
        final_client.logout()
    
    def test_complete_authentication_token_lifecycle(self, client):
        """Test complete token lifecycle from creation to expiration."""
        # Step 1: Login and get tokens
        success = client.login_user(USER_USERNAME, USER_PASSWORD)
        assert success, "Step 1 - Initial login failed"
        
        original_access_token = client.access_token
        original_refresh_token = client.refresh_token
        
        # Step 2: Use access token for API calls
        response = client.get("/users/me")
        assert response.status_code == 200, "Step 2 - API call with access token failed"
        
        # Step 3: Refresh the access token
        import time
        time.sleep(1)  # Ensure new token will be different
        
        refresh_success = client.refresh_access_token()
        assert refresh_success, "Step 3 - Token refresh failed"
        
        new_access_token = client.access_token
        new_refresh_token = client.refresh_token
        
        # Step 4: Verify tokens are different
        assert new_access_token != original_access_token, "Step 4 - Access token not refreshed"
        assert new_refresh_token != original_refresh_token, "Step 4 - Refresh token not refreshed"
        
        # Step 5: Use new access token
        response = client.get("/users/me")
        assert response.status_code == 200, "Step 5 - API call with new access token failed"
        
        # Step 6: Try to use old refresh token (should fail)
        old_client = PermisoClient()
        old_client.refresh_token = original_refresh_token
        old_refresh_success = old_client.refresh_access_token()
        assert not old_refresh_success, "Step 6 - Old refresh token still works"
        
        # Step 7: Logout to revoke all tokens
        response = client.post("/auth/logout")
        assert response.status_code == 200, "Step 7 - Logout failed"
        
        # Step 8: Verify tokens are revoked
        response = client.get("/users/me")
        assert response.status_code == 401, "Step 8 - Tokens not properly revoked"
        
        # Step 9: Verify refresh token is also revoked
        revoked_client = PermisoClient()
        revoked_client.refresh_token = new_refresh_token
        revoked_refresh_success = revoked_client.refresh_access_token()
        assert not revoked_refresh_success, "Step 9 - Refresh token not properly revoked"
    
    def test_user_profile_management_complete_flow(self, client, test_user_data):
        """Test complete user profile management flow."""
        # Step 1: Register user
        response = client.post("/users/register", json=test_user_data)
        assert response.status_code == 201, "Step 1 - User registration failed"
        
        # Step 2: Login
        login_success = client.login_user(test_user_data["username"], test_user_data["password"])
        assert login_success, "Step 2 - Login failed"
        
        # Step 3: Get initial profile
        response = client.get("/users/me")
        assert response.status_code == 200, "Step 3 - Get initial profile failed"
        initial_profile = response.json()
        
        # Step 4: Update profile multiple times
        updates = [
            {"first_name": "Updated First"},
            {"last_name": "Updated Last"},
            {"bio": "Updated bio"},
            {"display_name": "Updated Display Name"}
        ]
        
        for i, update_data in enumerate(updates, 4):
            response = client.put("/users/me", json=update_data)
            assert response.status_code == 200, f"Step {i} - Profile update failed"
            
            # Verify update was applied
            updated_profile = response.json()
            for key, value in update_data.items():
                assert updated_profile[key] == value, f"Step {i} - {key} not updated correctly"
        
        # Step 8: Get final profile and verify all updates
        response = client.get("/users/me")
        assert response.status_code == 200, "Step 8 - Get final profile failed"
        final_profile = response.json()
        
        assert final_profile["first_name"] == "Updated First"
        assert final_profile["last_name"] == "Updated Last"
        assert final_profile["bio"] == "Updated bio"
        assert final_profile["display_name"] == "Updated Display Name"
        
        # Step 9: Verify unchanged fields remain the same
        assert final_profile["username"] == initial_profile["username"]
        assert final_profile["email"] == initial_profile["email"]
        assert final_profile["id"] == initial_profile["id"]
        
        # Step 10: Logout
        client.logout()