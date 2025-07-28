"""Test configuration and fixtures for Permiso functional tests."""

import pytest
import requests
import json
import os
from typing import Dict, Any, Optional
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for testing
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Test configuration
BASE_URL = os.getenv("PERMISO_BASE_URL", "https://localhost:443")
API_BASE = "/api/v1"
VERIFY_SSL = False
TIMEOUT = 30

# Test credentials (should be configured in environment)
ADMIN_USERNAME = os.getenv("TEST_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("TEST_ADMIN_PASSWORD", "AdminPass123!")
USER_USERNAME = os.getenv("TEST_USER_USERNAME", "testuser")
USER_PASSWORD = os.getenv("TEST_USER_PASSWORD", "UserPass123!")
CLIENT_ID = os.getenv("TEST_CLIENT_ID", "test-client-001")
CLIENT_SECRET = os.getenv("TEST_CLIENT_SECRET", "test-secret-123456789")


class PermisoClient:
    """HTTP client for Permiso API testing."""
    
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.api_base = API_BASE
        self.session = requests.Session()
        self.session.verify = VERIFY_SSL
        self.session.timeout = TIMEOUT
        self.access_token = None
        self.refresh_token = None
        
        # Set default headers
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Permiso-Functional-Test/1.0"
        })
    
    def request(self, method: str, endpoint: str, **kwargs):
        """Make HTTP request to API endpoint."""
        url = f"{self.base_url}{self.api_base}{endpoint}"
        if not endpoint.startswith('/'):
            url = f"{self.base_url}{self.api_base}/{endpoint}"
        
        # Add auth header if token available
        headers = kwargs.get('headers', {})
        if self.access_token:
            headers['Authorization'] = f"Bearer {self.access_token}"
        kwargs['headers'] = headers
        
        return self.session.request(method, url, **kwargs)
    
    def get(self, endpoint: str, **kwargs):
        """Make GET request."""
        return self.request("GET", endpoint, **kwargs)
    
    def post(self, endpoint: str, **kwargs):
        """Make POST request."""
        return self.request("POST", endpoint, **kwargs)
    
    def put(self, endpoint: str, **kwargs):
        """Make PUT request."""
        return self.request("PUT", endpoint, **kwargs)
    
    def patch(self, endpoint: str, **kwargs):
        """Make PATCH request."""
        return self.request("PATCH", endpoint, **kwargs)
    
    def delete(self, endpoint: str, **kwargs):
        """Make DELETE request."""
        return self.request("DELETE", endpoint, **kwargs)
    
    def login_user(self, username: str, password: str) -> bool:
        """Login user and store tokens."""
        data = {
            "username": username,
            "password": password,
            "grant_type": "password"
        }
        
        response = self.post("/auth/token", data=data)
        if response.status_code == 200:
            token_data = response.json()
            self.access_token = token_data.get("access_token")
            self.refresh_token = token_data.get("refresh_token")
            return True
        return False
    
    def login_service_client(self, client_id: str, client_secret: str, scope: str = None) -> bool:
        """Login service client and store token."""
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials"
        }
        if scope:
            data["scope"] = scope
        
        response = self.post("/auth/service-token", data=data)
        if response.status_code == 200:
            token_data = response.json()
            self.access_token = token_data.get("access_token")
            return True
        return False
    
    def refresh_access_token(self) -> bool:
        """Refresh access token using refresh token."""
        if not self.refresh_token:
            return False
        
        data = {"refresh_token": self.refresh_token}
        response = self.post("/auth/refresh", json=data)
        
        if response.status_code == 200:
            token_data = response.json()
            self.access_token = token_data.get("access_token")
            self.refresh_token = token_data.get("refresh_token")
            return True
        return False
    
    def logout(self):
        """Logout and clear tokens."""
        if self.access_token:
            try:
                self.post("/auth/logout")
            except:
                pass  # Ignore logout errors during cleanup
        self.access_token = None
        self.refresh_token = None
        
        # Clear auth header
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']


@pytest.fixture
def client():
    """Create API client."""
    return PermisoClient()


@pytest.fixture
def admin_client():
    """Create authenticated admin client."""
    client = PermisoClient()
    success = client.login_user(ADMIN_USERNAME, ADMIN_PASSWORD)
    if not success:
        pytest.skip("Failed to authenticate admin user")
    yield client
    client.logout()


@pytest.fixture
def user_client():
    """Create authenticated user client."""
    client = PermisoClient()
    success = client.login_user(USER_USERNAME, USER_PASSWORD)
    if not success:
        pytest.skip("Failed to authenticate regular user")
    yield client
    client.logout()


@pytest.fixture
def service_client():
    """Create authenticated service client."""
    client = PermisoClient()
    success = client.login_service_client(CLIENT_ID, CLIENT_SECRET)
    if not success:
        pytest.skip("Failed to authenticate service client")
    yield client


@pytest.fixture
def test_user_data():
    """Generate unique test user data."""
    import uuid
    unique_id = str(uuid.uuid4())[:8]
    
    return {
        "username": f"testuser_{unique_id}",
        "email": f"test_{unique_id}@permiso.test",
        "password": "TestPass123!",
        "first_name": "Test",
        "last_name": "User",
        "display_name": f"Test User {unique_id}",
        "bio": "Test user for functional testing"
    }


@pytest.fixture
def test_role_data():
    """Generate unique test role data."""
    import uuid
    unique_id = str(uuid.uuid4())[:8]
    
    return {
        "name": f"test_role_{unique_id}",
        "description": f"Test role for functional testing {unique_id}",
        "scope_ids": []
    }


@pytest.fixture
def test_service_client_data():
    """Generate unique test service client data."""
    import uuid
    unique_id = str(uuid.uuid4())[:8]
    
    return {
        "client_id": f"test_client_{unique_id}",
        "name": f"Test Client {unique_id}",
        "description": f"Test service client for functional testing {unique_id}",
        "client_type": "confidential",
        "is_active": True,
        "is_trusted": False,
        "scope_ids": []
    }


# Helper functions for test validation
def assert_valid_user_response(user_data: dict, expected_username: str = None):
    """Assert that user response has valid structure."""
    assert "id" in user_data, "User ID not in response"
    assert "username" in user_data, "Username not in response"
    assert "email" in user_data, "Email not in response"
    assert "created_at" in user_data, "Created timestamp not in response"
    assert "is_active" in user_data, "Active status not in response"
    assert "password" not in user_data, "Password exposed in response"
    assert "password_hash" not in user_data, "Password hash exposed in response"
    
    if expected_username:
        assert user_data["username"] == expected_username, f"Username mismatch: expected {expected_username}, got {user_data['username']}"


def assert_valid_token_response(token_data: dict):
    """Assert that token response has valid structure."""
    assert "access_token" in token_data, "Access token not in response"
    assert "token_type" in token_data, "Token type not in response"
    assert "expires_in" in token_data, "Token expiry not in response"
    assert token_data["token_type"] == "Bearer", f"Invalid token type: {token_data['token_type']}"
    assert isinstance(token_data["expires_in"], int), "Token expiry not integer"
    assert token_data["expires_in"] > 0, "Token expiry not positive"


def assert_error_response(response_data: dict, expected_error: str = None):
    """Assert that error response has valid structure."""
    assert "error" in response_data, "Error field not in response"
    assert "error_description" in response_data, "Error description not in response"
    
    if expected_error:
        assert response_data["error"] == expected_error, f"Error type mismatch: expected {expected_error}, got {response_data['error']}"