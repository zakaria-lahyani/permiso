"""Integration tests for Redis functionality."""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock
from redis.asyncio import Redis
from redis.exceptions import RedisError, ConnectionError

from app.config.redis import RedisManager, get_redis_manager, create_redis_client
from app.config.settings import Settings


@pytest.mark.integration
class TestRedisIntegration:
    """Integration tests for Redis operations."""

    @pytest.fixture
    async def redis_client(self):
        """Create a Redis client for testing."""
        # Use a test Redis database
        test_redis_url = "redis://localhost:6379/15"
        client = create_redis_client(test_redis_url)

        # Clean up any existing test data
        await client.flushdb()

        yield client

        # Clean up after tests
        await client.flushdb()
        await client.close()

    @pytest.fixture
    async def redis_manager(self):
        """Create a RedisManager for testing."""
        mock_settings = Settings()
        mock_settings.redis_url = "redis://localhost:6379/15"

        manager = RedisManager(mock_settings)

        # Clean up any existing test data
        await manager.client.flushdb()

        yield manager

        # Clean up after tests
        await manager.client.flushdb()
        await manager.close()

    @pytest.mark.asyncio
    async def test_redis_basic_operations(self, redis_client):
        """Test basic Redis operations."""
        # Test SET and GET
        await redis_client.set("test_key", "test_value")
        value = await redis_client.get("test_key")
        assert value == "test_value"

        # Test EXISTS
        exists = await redis_client.exists("test_key")
        assert exists == 1

        # Test DELETE
        deleted = await redis_client.delete("test_key")
        assert deleted == 1

        # Verify deletion
        value = await redis_client.get("test_key")
        assert value is None

    @pytest.mark.asyncio
    async def test_redis_expiration(self, redis_client):
        """Test Redis key expiration."""
        # Set key with expiration
        await redis_client.set("expire_key", "expire_value", ex=2)

        # Key should exist initially
        value = await redis_client.get("expire_key")
        assert value == "expire_value"

        # Check TTL
        ttl = await redis_client.ttl("expire_key")
        assert 0 < ttl <= 2

        # Wait for expiration
        await asyncio.sleep(3)

        # Key should be expired
        value = await redis_client.get("expire_key")
        assert value is None

    @pytest.mark.asyncio
    async def test_redis_hash_operations(self, redis_client):
        """Test Redis hash operations."""
        # Set hash fields
        await redis_client.hset("test_hash", "field1", "value1")
        await redis_client.hset("test_hash", "field2", "value2")

        # Get hash field
        value = await redis_client.hget("test_hash", "field1")
        assert value == "value1"

        # Get all hash fields
        hash_data = await redis_client.hgetall("test_hash")
        assert hash_data == {"field1": "value1", "field2": "value2"}

        # Delete hash field
        deleted = await redis_client.hdel("test_hash", "field1")
        assert deleted == 1

        # Verify field deletion
        value = await redis_client.hget("test_hash", "field1")
        assert value is None

    @pytest.mark.asyncio
    async def test_redis_list_operations(self, redis_client):
        """Test Redis list operations."""
        # Push to list
        await redis_client.lpush("test_list", "item1", "item2", "item3")

        # Get list length
        length = await redis_client.llen("test_list")
        assert length == 3

        # Pop from list
        item = await redis_client.rpop("test_list")
        assert item == "item1"

        # Get list range
        items = await redis_client.lrange("test_list", 0, -1)
        assert items == ["item3", "item2"]

    @pytest.mark.asyncio
    async def test_redis_set_operations(self, redis_client):
        """Test Redis set operations."""
        # Add to set
        await redis_client.sadd("test_set", "member1", "member2", "member3")

        # Check set size
        size = await redis_client.scard("test_set")
        assert size == 3

        # Check membership
        is_member = await redis_client.sismember("test_set", "member1")
        assert is_member is True

        # Get all members
        members = await redis_client.smembers("test_set")
        assert members == {"member1", "member2", "member3"}

        # Remove member
        removed = await redis_client.srem("test_set", "member1")
        assert removed == 1

    @pytest.mark.asyncio
    async def test_redis_pipeline_operations(self, redis_client):
        """Test Redis pipeline operations."""
        # Create pipeline
        pipe = redis_client.pipeline()

        # Add operations to pipeline
        pipe.set("pipe_key1", "pipe_value1")
        pipe.set("pipe_key2", "pipe_value2")
        pipe.get("pipe_key1")
        pipe.get("pipe_key2")

        # Execute pipeline
        results = await pipe.execute()

        # Check results
        assert results[0] is True  # SET result
        assert results[1] is True  # SET result
        assert results[2] == "pipe_value1"  # GET result
        assert results[3] == "pipe_value2"  # GET result

    @pytest.mark.asyncio
    async def test_redis_transaction_operations(self, redis_client):
        """Test Redis transaction operations."""
        # Start transaction
        pipe = redis_client.pipeline(transaction=True)

        # Add operations
        pipe.multi()
        pipe.set("trans_key", "trans_value")
        pipe.incr("counter")

        # Execute transaction
        results = await pipe.execute()

        # Check results
        assert results[0] is True  # SET result
        assert results[1] == 1     # INCR result

    @pytest.mark.asyncio
    async def test_redis_manager_operations(self, redis_manager):
        """Test RedisManager operations."""
        # Test set and get
        result = await redis_manager.set("manager_key", "manager_value", ex=3600)
        assert result is True

        value = await redis_manager.get("manager_key")
        assert value == "manager_value"

        # Test exists
        exists = await redis_manager.exists("manager_key")
        assert exists is True

        # Test TTL
        ttl = await redis_manager.ttl("manager_key")
        assert 0 < ttl <= 3600

        # Test delete
        deleted = await redis_manager.delete("manager_key")
        assert deleted == 1

        # Verify deletion
        exists = await redis_manager.exists("manager_key")
        assert exists is False

    @pytest.mark.asyncio
    async def test_redis_manager_multiple_keys(self, redis_manager):
        """Test RedisManager operations with multiple keys."""
        # Set multiple keys
        await redis_manager.set("key1", "value1")
        await redis_manager.set("key2", "value2")
        await redis_manager.set("key3", "value3")

        # Delete multiple keys
        deleted = await redis_manager.delete("key1", "key2", "key3")
        assert deleted == 3

        # Verify all keys are deleted
        for key in ["key1", "key2", "key3"]:
            exists = await redis_manager.exists(key)
            assert exists is False

    @pytest.mark.asyncio
    async def test_redis_health_check(self, redis_manager):
        """Test Redis health check."""
        # Health check should pass
        is_healthy = await redis_manager.health_check()
        assert is_healthy is True

    @pytest.mark.asyncio
    async def test_redis_connection_recovery(self, redis_client):
        """Test Redis connection recovery after failure."""
        # This test would require actually stopping/starting Redis
        # For now, we'll test the error handling

        # Simulate connection error
        with patch.object(redis_client, 'ping', side_effect=ConnectionError("Connection lost")):
            with pytest.raises(ConnectionError):
                await redis_client.ping()

        # Normal operation should work after "recovery"
        result = await redis_client.ping()
        assert result is True

    @pytest.mark.asyncio
    async def test_redis_concurrent_operations(self, redis_client):
        """Test concurrent Redis operations."""
        async def set_key(key, value):
            await redis_client.set(key, value)
            return await redis_client.get(key)

        # Run concurrent operations
        tasks = [
            set_key(f"concurrent_key_{i}", f"concurrent_value_{i}")
            for i in range(10)
        ]

        results = await asyncio.gather(*tasks)

        # Verify all operations completed successfully
        for i, result in enumerate(results):
            assert result == f"concurrent_value_{i}"

    @pytest.mark.asyncio
    async def test_redis_large_data_operations(self, redis_client):
        """Test Redis operations with large data."""
        # Create large string (1MB)
        large_data = "x" * (1024 * 1024)

        # Set large data
        await redis_client.set("large_key", large_data)

        # Get large data
        retrieved_data = await redis_client.get("large_key")
        assert retrieved_data == large_data

        # Clean up
        await redis_client.delete("large_key")

    @pytest.mark.asyncio
    async def test_redis_pattern_operations(self, redis_client):
        """Test Redis pattern-based operations."""
        # Set keys with pattern
        keys = ["user:1:name", "user:1:email", "user:2:name", "user:2:email"]
        for key in keys:
            await redis_client.set(key, f"value_for_{key}")

        # Find keys by pattern
        found_keys = await redis_client.keys("user:1:*")
        assert len(found_keys) == 2
        assert "user:1:name" in found_keys
        assert "user:1:email" in found_keys

        # Clean up
        await redis_client.delete(*keys)

    @pytest.mark.asyncio
    async def test_redis_json_serialization(self, redis_manager):
        """Test Redis with JSON data serialization."""
        import json

        # Test data
        test_data = {
            "user_id": 123,
            "username": "testuser",
            "roles": ["user", "admin"],
            "metadata": {"created_at": "2023-01-01", "active": True}
        }

        # Serialize and store
        json_data = json.dumps(test_data)
        await redis_manager.set("user:123", json_data, ex=3600)

        # Retrieve and deserialize
        retrieved_json = await redis_manager.get("user:123")
        retrieved_data = json.loads(retrieved_json)

        assert retrieved_data == test_data

    @pytest.mark.asyncio
    async def test_redis_session_storage(self, redis_manager):
        """Test Redis as session storage."""
        session_id = "session_123456"
        session_data = {
            "user_id": "user_789",
            "username": "sessionuser",
            "login_time": "2023-01-01T10:00:00Z",
            "permissions": ["read", "write"]
        }

        import json

        # Store session
        await redis_manager.set(
            f"session:{session_id}",
            json.dumps(session_data),
            ex=1800  # 30 minutes
        )

        # Retrieve session
        stored_session = await redis_manager.get(f"session:{session_id}")
        assert stored_session is not None

        retrieved_session = json.loads(stored_session)
        assert retrieved_session == session_data

        # Check session TTL
        ttl = await redis_manager.ttl(f"session:{session_id}")
        assert 0 < ttl <= 1800

    @pytest.mark.asyncio
    async def test_redis_cache_invalidation(self, redis_manager):
        """Test Redis cache invalidation patterns."""
        # Set cache entries
        cache_keys = [
            "cache:user:123",
            "cache:user:456",
            "cache:post:789",
            "cache:comment:101"
        ]

        for key in cache_keys:
            await redis_manager.set(key, f"cached_data_for_{key}", ex=3600)

        # Verify all keys exist
        for key in cache_keys:
            exists = await redis_manager.exists(key)
            assert exists is True

        # Invalidate user caches
        user_cache_keys = [key for key in cache_keys if "user" in key]
        deleted = await redis_manager.delete(*user_cache_keys)
        assert deleted == 2

        # Verify user caches are gone, others remain
        for key in user_cache_keys:
            exists = await redis_manager.exists(key)
            assert exists is False

        for key in cache_keys:
            if "user" not in key:
                exists = await redis_manager.exists(key)
                assert exists is True

    @pytest.mark.asyncio
    async def test_redis_rate_limiting(self, redis_client):
        """Test Redis for rate limiting implementation."""
        user_id = "user_123"
        rate_limit_key = f"rate_limit:{user_id}"

        # Simulate rate limiting (5 requests per minute)
        max_requests = 5
        window_seconds = 60

        # Make requests
        for i in range(max_requests + 2):  # Exceed limit
            # Increment counter
            current_count = await redis_client.incr(rate_limit_key)

            if current_count == 1:
                # Set expiration on first request
                await redis_client.expire(rate_limit_key, window_seconds)

            if current_count <= max_requests:
                # Request allowed
                assert current_count <= max_requests
            else:
                # Request should be rate limited
                assert current_count > max_requests

                # Check TTL for reset time
                ttl = await redis_client.ttl(rate_limit_key)
                assert ttl > 0

    @pytest.mark.asyncio
    async def test_redis_distributed_lock(self, redis_client):
        """Test Redis distributed locking mechanism."""
        lock_key = "lock:resource_123"
        lock_value = "lock_owner_456"
        lock_timeout = 10

        # Acquire lock
        acquired = await redis_client.set(
            lock_key,
            lock_value,
            nx=True,  # Only set if not exists
            ex=lock_timeout
        )
        assert acquired is True

        # Try to acquire same lock (should fail)
        acquired_again = await redis_client.set(
            lock_key,
            "different_owner",
            nx=True,
            ex=lock_timeout
        )
        assert acquired_again is None

        # Release lock (only if we own it)
        current_value = await redis_client.get(lock_key)
        if current_value == lock_value:
            deleted = await redis_client.delete(lock_key)
            assert deleted == 1

        # Now lock can be acquired again
        acquired_after_release = await redis_client.set(
            lock_key,
            "new_owner",
            nx=True,
            ex=lock_timeout
        )
        assert acquired_after_release is True


@pytest.mark.integration
class TestRedisManagerIntegration:
    """Integration tests specifically for RedisManager."""

    @pytest.mark.asyncio
    async def test_redis_manager_singleton_behavior(self):
        """Test RedisManager singleton behavior."""
        # Clear cache to ensure clean test
        get_redis_manager.cache_clear()

        with patch('app.config.redis.get_settings') as mock_get_settings:
            mock_settings = Settings()
            mock_settings.redis_url = "redis://localhost:6379/15"
            mock_get_settings.return_value = mock_settings

            # Get multiple instances
            manager1 = get_redis_manager()
            manager2 = get_redis_manager()

            # Should be the same instance
            assert manager1 is manager2

    @pytest.mark.asyncio
    async def test_redis_manager_context_manager_integration(self):
        """Test RedisManager as context manager in integration scenario."""
        mock_settings = Settings()
        mock_settings.redis_url = "redis://localhost:6379/15"

        async with RedisManager(mock_settings) as manager:
            # Test operations within context
            await manager.set("context_key", "context_value")
            value = await manager.get("context_key")
            assert value == "context_value"

            # Test health check
            is_healthy = await manager.health_check()
            assert is_healthy is True

        # Manager should be closed after context

    @pytest.mark.asyncio
    async def test_redis_manager_error_recovery(self):
        """Test RedisManager error recovery."""
        mock_settings = Settings()
        mock_settings.redis_url = "redis://localhost:6379/15"

        manager = RedisManager(mock_settings)

        try:
            # Normal operation
            await manager.set("recovery_key", "recovery_value")
            value = await manager.get("recovery_key")
            assert value == "recovery_value"

            # Simulate error and recovery
            with patch.object(manager.client, 'get', side_effect=RedisError("Temporary error")):
                with pytest.raises(RedisError):
                    await manager.get("recovery_key")

            # Should work again after "recovery"
            value = await manager.get("recovery_key")
            assert value == "recovery_value"

        finally:
            await manager.close()