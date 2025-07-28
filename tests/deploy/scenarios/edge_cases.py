"""Edge cases test scenarios for Permiso functional testing."""

import pytest
import uuid
import time
import string
import random
from conftest import (
    PermisoClient,
    USER_USERNAME,
    USER_PASSWORD,
    assert_valid_user_response,
    assert_error_response
)


class TestEdgeCaseScenarios:
    """Test edge cases, boundary conditions, and special scenarios."""
    
    def test_special_characters_in_user_data(self, client):
        """Test user registration and updates with special characters."""
        # Test various special characters in different fields
        special_chars_tests = [
            {
                "name": "unicode_characters",
                "data": {
                    "username": f"user_测试_{uuid.uuid4().hex[:6]}",
                    "email": f"test_测试_{uuid.uuid4().hex[:6]}@example.com",
                    "password": "TestPass123!",
                    "first_name": "测试",
                    "last_name": "用户",
                    "display_name": "测试用户 🚀",
                    "bio": "Bio with émojis 🎉 and spëcial chars àáâãäå"
                }
            },
            {
                "name": "special_symbols",
                "data": {
                    "username": f"user_sym_{uuid.uuid4().hex[:6]}",
                    "email": f"test.sym+tag_{uuid.uuid4().hex[:6]}@example.com",
                    "password": "P@ssw0rd!#$%",
                    "first_name": "John-Paul",
                    "last_name": "O'Connor",
                    "display_name": "John-Paul O'Connor Jr.",
                    "bio": "Bio with symbols: @#$%^&*()_+-=[]{}|;':\",./<>?"
                }
            },
            {
                "name": "whitespace_handling",
                "data": {
                    "username": f"user_space_{uuid.uuid4().hex[:6]}",
                    "email": f"test_space_{uuid.uuid4().hex[:6]}@example.com",
                    "password": "TestPass123!",
                    "first_name": "  John  ",  # Leading/trailing spaces
                    "last_name": "  Doe  ",
                    "display_name": "John   Doe",  # Multiple spaces
                    "bio": "Bio with\nnewlines\tand\ttabs"
                }
            }
        ]
        
        for test_case in special_chars_tests:
            test_data = test_case["data"]
            
            response = client.post("/users/register", json=test_data)
            
            # Registration might succeed or fail depending on validation rules
            if response.status_code == 201:
                # If registration succeeded, verify data handling
                user_data = response.json()
                assert_valid_user_response(user_data, test_data["username"])
                
                # Login with the created user to test authentication
                test_client = PermisoClient()
                login_success = test_client.login_user(test_data["username"], test_data["password"])
                
                if login_success:
                    # Test profile retrieval
                    profile_response = test_client.get("/users/me")
                    assert profile_response.status_code == 200, \
                        f"Profile retrieval failed for {test_case['name']}"
                    
                    profile_data = profile_response.json()
                    
                    # Verify special characters are preserved (or properly handled)
                    assert profile_data["username"] == test_data["username"]
                    assert profile_data["email"] == test_data["email"]
                    
                    test_client.logout()
                
            elif response.status_code in [400, 422]:
                # Registration failed due to validation - this is acceptable
                error_data = response.json()
                assert_error_response(error_data)
            else:
                pytest.fail(f"Unexpected response for {test_case['name']}: {response.status_code}")
    
    def test_boundary_value_field_lengths(self, client):
        """Test boundary values for field lengths."""
        base_data = {
            "username": f"boundary_{uuid.uuid4().hex[:8]}",
            "email": f"boundary_{uuid.uuid4().hex[:8]}@example.com",
            "password": "BoundaryPass123!"
        }
        
        # Test various field length boundaries
        boundary_tests = [
            {
                "name": "minimum_username_length",
                "field": "username",
                "value": "ab"  # Very short username
            },
            {
                "name": "maximum_username_length",
                "field": "username", 
                "value": "a" * 100  # Very long username
            },
            {
                "name": "minimum_password_length",
                "field": "password",
                "value": "Pass1!"  # Short password
            },
            {
                "name": "maximum_password_length",
                "field": "password",
                "value": "P" + "a" * 200 + "ss1!"  # Very long password
            },
            {
                "name": "very_long_email",
                "field": "email",
                "value": f"{'a' * 100}@{'b' * 100}.com"  # Very long email
            },
            {
                "name": "very_long_name",
                "field": "first_name",
                "value": "A" * 200  # Very long first name
            },
            {
                "name": "very_long_bio",
                "field": "bio",
                "value": "Bio content " * 1000  # Very long bio
            }
        ]
        
        for test_case in boundary_tests:
            test_data = base_data.copy()
            test_data[test_case["field"]] = test_case["value"]
            
            # Ensure unique username for each test
            if test_case["field"] != "username":
                test_data["username"] = f"boundary_{uuid.uuid4().hex[:8]}"
            
            response = client.post("/users/register", json=test_data)
            
            # Response should be either success or validation error
            assert response.status_code in [201, 400, 422], \
                f"Unexpected status for {test_case['name']}: {response.status_code}"
            
            if response.status_code == 201:
                # Registration succeeded - verify data was stored correctly
                user_data = response.json()
                if test_case["field"] in user_data:
                    stored_value = user_data[test_case["field"]]
                    # Value might be truncated or normalized
                    assert len(stored_value) > 0, f"Field {test_case['field']} is empty"
    
    def test_concurrent_user_operations(self, admin_client, test_user_data):
        """Test concurrent operations on the same user."""
        # Create a test user first
        response = admin_client.post("/users", json=test_user_data)
        assert response.status_code == 201, "Test user creation failed"
        created_user = response.json()
        user_id = created_user["id"]
        
        # Simulate concurrent updates
        update_data_1 = {"first_name": "Concurrent Update 1"}
        update_data_2 = {"first_name": "Concurrent Update 2"}
        
        # Make concurrent requests (as close as possible)
        response1 = admin_client.put(f"/users/{user_id}", json=update_data_1)
        response2 = admin_client.put(f"/users/{user_id}", json=update_data_2)
        
        # Both requests should succeed (last one wins)
        assert response1.status_code == 200, "First concurrent update failed"
        assert response2.status_code == 200, "Second concurrent update failed"
        
        # Verify final state
        response = admin_client.get(f"/users/{user_id}")
        assert response.status_code == 200, "User retrieval failed"
        final_user = response.json()
        
        # Final state should reflect one of the updates
        assert final_user["first_name"] in ["Concurrent Update 1", "Concurrent Update 2"], \
            "Neither concurrent update was applied"
        
        # Cleanup
        admin_client.delete(f"/users/{user_id}")
    
    def test_rapid_authentication_attempts(self, client):
        """Test rapid successive authentication attempts."""
        # Test rapid login attempts with valid credentials
        login_results = []
        
        for i in range(5):
            test_client = PermisoClient()
            success = test_client.login_user(USER_USERNAME, USER_PASSWORD)
            login_results.append(success)
            
            if success:
                test_client.logout()
        
        # Most attempts should succeed (unless rate limiting is very aggressive)
        successful_logins = sum(login_results)
        assert successful_logins >= 3, \
            f"Too many rapid login attempts failed: {successful_logins}/5"
        
        # Test rapid login attempts with invalid credentials
        invalid_results = []
        
        for i in range(3):  # Fewer attempts to avoid account lockout
            test_client = PermisoClient()
            success = test_client.login_user(USER_USERNAME, "wrong_password")
            invalid_results.append(success)
        
        # All invalid attempts should fail
        assert sum(invalid_results) == 0, "Invalid credentials should not succeed"
    
    def test_token_refresh_edge_cases(self, client):
        """Test edge cases in token refresh scenarios."""
        # Login to get initial tokens
        success = client.login_user(USER_USERNAME, USER_PASSWORD)
        assert success, "Initial login failed"
        
        original_refresh_token = client.refresh_token
        
        # Test 1: Multiple rapid refresh attempts with same token
        refresh_results = []
        
        for i in range(3):
            test_client = PermisoClient()
            test_client.refresh_token = original_refresh_token
            success = test_client.refresh_access_token()
            refresh_results.append(success)
        
        # Only first refresh should succeed (token should be invalidated after use)
        successful_refreshes = sum(refresh_results)
        assert successful_refreshes <= 1, \
            f"Multiple refreshes with same token succeeded: {successful_refreshes}"
        
        # Test 2: Refresh with slightly modified token
        if original_refresh_token:
            modified_token = original_refresh_token[:-1] + "X"  # Change last character
            test_client = PermisoClient()
            test_client.refresh_token = modified_token
            success = test_client.refresh_access_token()
            assert not success, "Modified refresh token should not work"
        
        # Cleanup
        client.logout()
    
    def test_session_management_edge_cases(self, user_client):
        """Test edge cases in session management."""
        # Test 1: Get sessions list
        response = user_client.get("/sessions")
        if response.status_code == 200:
            sessions_data = response.json()
            assert "sessions" in sessions_data, "Sessions list not in response"
            
            if sessions_data["sessions"]:
                # Test operations on first session
                session_id = sessions_data["sessions"][0]["session_id"]
                
                # Test session renewal
                response = user_client.post(f"/sessions/{session_id}/renew")
                assert response.status_code in [200, 404, 403], \
                    f"Unexpected session renewal response: {response.status_code}"
                
                # Test session deletion (but not current session)
                if len(sessions_data["sessions"]) > 1:
                    other_session_id = sessions_data["sessions"][1]["session_id"]
                    response = user_client.delete(f"/sessions/{other_session_id}")
                    assert response.status_code in [200, 204, 404, 403], \
                        f"Unexpected session deletion response: {response.status_code}"
        
        # Test 2: Invalid session operations
        fake_session_id = str(uuid.uuid4())
        
        response = user_client.post(f"/sessions/{fake_session_id}/renew")
        assert response.status_code in [404, 403], \
            f"Expected 404/403 for fake session renewal, got {response.status_code}"
        
        response = user_client.delete(f"/sessions/{fake_session_id}")
        assert response.status_code in [404, 403], \
            f"Expected 404/403 for fake session deletion, got {response.status_code}"
    
    def test_large_payload_handling(self, client):
        """Test handling of large request payloads."""
        # Create user data with large fields
        large_bio = "This is a very long bio. " * 1000  # ~25KB bio
        large_display_name = "Very Long Display Name " * 100  # ~2KB display name
        
        large_user_data = {
            "username": f"large_payload_{uuid.uuid4().hex[:8]}",
            "email": f"large_{uuid.uuid4().hex[:8]}@example.com",
            "password": "LargePayloadPass123!",
            "first_name": "Large",
            "last_name": "Payload",
            "display_name": large_display_name,
            "bio": large_bio
        }
        
        response = client.post("/users/register", json=large_user_data)
        
        # Server should either accept the large payload or reject it gracefully
        assert response.status_code in [201, 400, 413, 422], \
            f"Unexpected response for large payload: {response.status_code}"
        
        if response.status_code == 201:
            # If accepted, verify data was stored
            user_data = response.json()
            assert_valid_user_response(user_data, large_user_data["username"])
            
            # Login and test profile retrieval with large data
            test_client = PermisoClient()
            login_success = test_client.login_user(large_user_data["username"], large_user_data["password"])
            
            if login_success:
                profile_response = test_client.get("/users/me")
                assert profile_response.status_code == 200, "Profile retrieval with large data failed"
                test_client.logout()
    
    def test_null_and_empty_value_handling(self, client, user_client):
        """Test handling of null and empty values."""
        # Test registration with null/empty values
        null_value_tests = [
            {
                "name": "null_optional_fields",
                "data": {
                    "username": f"null_test_{uuid.uuid4().hex[:8]}",
                    "email": f"null_{uuid.uuid4().hex[:8]}@example.com",
                    "password": "NullTestPass123!",
                    "first_name": None,
                    "last_name": None,
                    "display_name": None,
                    "bio": None
                }
            },
            {
                "name": "empty_optional_fields",
                "data": {
                    "username": f"empty_test_{uuid.uuid4().hex[:8]}",
                    "email": f"empty_{uuid.uuid4().hex[:8]}@example.com",
                    "password": "EmptyTestPass123!",
                    "first_name": "",
                    "last_name": "",
                    "display_name": "",
                    "bio": ""
                }
            }
        ]
        
        for test_case in null_value_tests:
            response = client.post("/users/register", json=test_case["data"])
            
            # Should either succeed or fail gracefully
            assert response.status_code in [201, 400, 422], \
                f"Unexpected response for {test_case['name']}: {response.status_code}"
            
            if response.status_code == 201:
                user_data = response.json()
                assert_valid_user_response(user_data, test_case["data"]["username"])
        
        # Test profile updates with null/empty values
        null_update_data = {
            "first_name": None,
            "bio": ""
        }
        
        response = user_client.put("/users/me", json=null_update_data)
        assert response.status_code in [200, 400, 422], \
            f"Unexpected response for null update: {response.status_code}"
    
    def test_case_sensitivity_edge_cases(self, client):
        """Test case sensitivity in various scenarios."""
        base_username = f"case_test_{uuid.uuid4().hex[:8]}"
        base_email = f"case_{uuid.uuid4().hex[:8]}@example.com"
        
        # Test 1: Username case sensitivity
        user_data_1 = {
            "username": base_username.lower(),
            "email": f"lower_{base_email}",
            "password": "CaseTestPass123!"
        }
        
        user_data_2 = {
            "username": base_username.upper(),
            "email": f"upper_{base_email}",
            "password": "CaseTestPass123!"
        }
        
        # Register both users
        response1 = client.post("/users/register", json=user_data_1)
        response2 = client.post("/users/register", json=user_data_2)
        
        # Both should succeed if usernames are case-sensitive
        # Or second should fail if usernames are case-insensitive
        assert response1.status_code == 201, "First user registration failed"
        assert response2.status_code in [201, 409], \
            f"Unexpected response for case variant: {response2.status_code}"
        
        # Test 2: Email case sensitivity
        if response1.status_code == 201 and response2.status_code == 201:
            # Test login with different cases
            test_client = PermisoClient()
            
            # Try login with original case
            success1 = test_client.login_user(user_data_1["username"], user_data_1["password"])
            if success1:
                test_client.logout()
            
            # Try login with different case
            success2 = test_client.login_user(user_data_1["username"].upper(), user_data_1["password"])
            if success2:
                test_client.logout()
            
            # At least one should work
            assert success1 or success2, "Neither case variant login worked"
    
    def test_unicode_normalization_edge_cases(self, client):
        """Test Unicode normalization edge cases."""
        # Test with Unicode characters that have multiple representations
        unicode_tests = [
            {
                "name": "composed_vs_decomposed",
                "username1": f"café_{uuid.uuid4().hex[:6]}",  # é as single character
                "username2": f"cafe\u0301_{uuid.uuid4().hex[:6]}",  # e + combining acute accent
            },
            {
                "name": "different_unicode_forms",
                "username1": f"naïve_{uuid.uuid4().hex[:6]}",
                "username2": f"nai\u0308ve_{uuid.uuid4().hex[:6]}",  # i + combining diaeresis
            }
        ]
        
        for test_case in unicode_tests:
            user_data_1 = {
                "username": test_case["username1"],
                "email": f"unicode1_{uuid.uuid4().hex[:8]}@example.com",
                "password": "UnicodePass123!"
            }
            
            user_data_2 = {
                "username": test_case["username2"],
                "email": f"unicode2_{uuid.uuid4().hex[:8]}@example.com",
                "password": "UnicodePass123!"
            }
            
            response1 = client.post("/users/register", json=user_data_1)
            response2 = client.post("/users/register", json=user_data_2)
            
            # Both should succeed if Unicode normalization is not applied
            # Or second should fail if normalization treats them as identical
            assert response1.status_code == 201, f"First Unicode user registration failed for {test_case['name']}"
            assert response2.status_code in [201, 409], \
                f"Unexpected response for Unicode variant in {test_case['name']}: {response2.status_code}"
    
    def test_time_based_edge_cases(self, client):
        """Test time-based edge cases and race conditions."""
        # Test rapid successive operations
        rapid_operations = []
        
        for i in range(5):
            unique_id = f"{uuid.uuid4().hex[:8]}_{i}"
            user_data = {
                "username": f"rapid_{unique_id}",
                "email": f"rapid_{unique_id}@example.com",
                "password": "RapidTestPass123!"
            }
            
            start_time = time.time()
            response = client.post("/users/register", json=user_data)
            end_time = time.time()
            
            rapid_operations.append({
                "response_code": response.status_code,
                "duration": end_time - start_time,
                "index": i
            })
        
        # All operations should succeed
        successful_ops = [op for op in rapid_operations if op["response_code"] == 201]
        assert len(successful_ops) == 5, \
            f"Not all rapid operations succeeded: {len(successful_ops)}/5"
        
        # Test timestamp consistency
        if successful_ops:
            # All operations should have reasonable response times
            max_duration = max(op["duration"] for op in successful_ops)
            assert max_duration < 10.0, \
                f"Some operations took too long: {max_duration}s"
    
    def test_resource_cleanup_edge_cases(self, admin_client):
        """Test resource cleanup and cascading operations."""
        # Create a user for testing cleanup
        user_data = {
            "username": f"cleanup_test_{uuid.uuid4().hex[:8]}",
            "email": f"cleanup_{uuid.uuid4().hex[:8]}@example.com",
            "password": "CleanupTestPass123!",
            "first_name": "Cleanup",
            "last_name": "Test"
        }
        
        response = admin_client.post("/users", json=user_data)
        assert response.status_code == 201, "Test user creation failed"
        created_user = response.json()
        user_id = created_user["id"]
        
        # Create multiple sessions for the user
        test_client = PermisoClient()
        login_success = test_client.login_user(user_data["username"], user_data["password"])
        assert login_success, "Test user login failed"
        
        # Get user profile to verify everything is working
        response = test_client.get("/users/me")
        assert response.status_code == 200, "User profile retrieval failed"
        
        # Delete the user (should clean up associated resources)
        response = admin_client.delete(f"/users/{user_id}")
        assert response.status_code == 204, "User deletion failed"
        
        # Verify user is deleted
        response = admin_client.get(f"/users/{user_id}")
        assert response.status_code == 404, "User still exists after deletion"
        
        # Verify user's session is invalidated
        response = test_client.get("/users/me")
        assert response.status_code == 401, "User session not invalidated after user deletion"