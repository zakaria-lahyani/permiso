"""Simple import test to verify the application setup."""

def test_app_import():
    """Test that the main app can be imported successfully."""
    try:
        from app.main import app
        assert app is not None
        assert app.title == "Keystone Authentication System"
        print("✅ App import successful!")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False


def test_models_import():
    """Test that all models can be imported successfully."""
    try:
        from app.models import User, Role, Scope, ServiceClient, RefreshToken
        from app.models import user_roles, role_scopes, service_client_scopes
        print("✅ Models import successful!")
        return True
    except ImportError as e:
        print(f"❌ Models import failed: {e}")
        return False


def test_config_import():
    """Test that configuration modules can be imported successfully."""
    try:
        from app.config.settings import settings
        from app.config.database import get_db, init_db, close_db
        from app.config.redis import get_redis, init_redis, close_redis
        print("✅ Config import successful!")
        return True
    except ImportError as e:
        print(f"❌ Config import failed: {e}")
        return False


def test_core_import():
    """Test that core modules can be imported successfully."""
    try:
        from app.core.jwt import jwt_service
        from app.core.password import hash_password, verify_password
        from app.core.security import get_current_user
        print("✅ Core modules import successful!")
        return True
    except ImportError as e:
        print(f"❌ Core modules import failed: {e}")
        return False


if __name__ == "__main__":
    print("🧪 Running import tests...")
    
    tests = [
        test_app_import,
        test_models_import,
        test_config_import,
        test_core_import,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
            failed += 1
    
    print(f"\n📊 Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All import tests passed! The application setup is working correctly.")
    else:
        print("⚠️  Some import tests failed. Please check the error messages above.")