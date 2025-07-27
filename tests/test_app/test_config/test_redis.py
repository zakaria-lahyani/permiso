# """Tests for Redis configuration and connection management."""
#
# import pytest
# import asyncio
# from unittest.mock import patch, AsyncMock, MagicMock
# from redis.asyncio import Redis
# from redis.exceptions import RedisError, ConnectionError, TimeoutError
#
# from app.config.redis import (
#     RedisManager,
#     get_redis_manager,
#     get_redis_client,
#     create_redis_client,
#     check_redis_connection,
#     init_redis
# )
# from app.config.settings import Settings
#
#
# class TestRedisManager:
#     """Test RedisManager class."""
#
#     @pytest.fixture
#     def mock_settings(self):
#         """Mock settings for testing."""
#         settings = MagicMock(spec=Settings)
#         settings.redis_url = "redis://localhost:6379/0"
#         settings.is_testing = False
#         settings.debug = False
#         return settings
#
#     @pytest.fixture
#     def redis_manager(self, mock_settings):
#         """Create RedisManager instance for testing."""
#         return RedisManager(mock_settings)
#
#     def test_redis_manager_initialization(self, mock_settings):
#         """Test RedisManager initialization."""
#         manager = RedisManager(mock_settings)
#
#         assert manager.settings == mock_settings
#         assert manager._client is None
#
#     def test_redis_manager_client_property(self, redis_manager, mock_settings):
#         """Test client property lazy initialization."""
#         with patch('app.config.redis.create_redis_client') as mock_create_client:
#             mock_client = AsyncMock(spec=Redis)
#             mock_create_client.return_value = mock_client
#
#             # First access should create client
#             client = redis_manager.client
#
#             assert client == mock_client
#             mock_create_client.assert_called_once_with(mock_settings.redis_url)
#
#             # Second access should return cached client
#             client2 = redis_manager.client
#             assert client2 == mock_client
#             assert mock_create_client.call_count == 1
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_close(self, redis_manager):
#         """Test close method."""
#         mock_client = AsyncMock(spec=Redis)
#         redis_manager._client = mock_client
#
#         await redis_manager.close()
#
#         mock_client.close.assert_called_once()
#         assert redis_manager._client is None
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_close_no_client(self, redis_manager):
#         """Test close method when no client exists."""
#         # Should not raise an error
#         await redis_manager.close()
#
#         assert redis_manager._client is None
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_health_check_success(self, redis_manager):
#         """Test successful health check."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.ping.return_value = True
#
#         with patch.object(redis_manager, 'client', mock_client):
#             result = await redis_manager.health_check()
#
#             assert result is True
#             mock_client.ping.assert_called_once()
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_health_check_failure(self, redis_manager):
#         """Test failed health check."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.ping.side_effect = RedisError("Connection failed")
#
#         with patch.object(redis_manager, 'client', mock_client):
#             result = await redis_manager.health_check()
#
#             assert result is False
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_get_success(self, redis_manager):
#         """Test successful get operation."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.get.return_value = b"test_value"
#
#         with patch.object(redis_manager, 'client', mock_client):
#             result = await redis_manager.get("test_key")
#
#             assert result == "test_value"
#             mock_client.get.assert_called_once_with("test_key")
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_get_not_found(self, redis_manager):
#         """Test get operation with non-existent key."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.get.return_value = None
#
#         with patch.object(redis_manager, 'client', mock_client):
#             result = await redis_manager.get("nonexistent_key")
#
#             assert result is None
#             mock_client.get.assert_called_once_with("nonexistent_key")
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_set_success(self, redis_manager):
#         """Test successful set operation."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.set.return_value = True
#
#         with patch.object(redis_manager, 'client', mock_client):
#             result = await redis_manager.set("test_key", "test_value", ex=3600)
#
#             assert result is True
#             mock_client.set.assert_called_once_with("test_key", "test_value", ex=3600)
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_set_with_ttl(self, redis_manager):
#         """Test set operation with TTL."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.set.return_value = True
#
#         with patch.object(redis_manager, 'client', mock_client):
#             result = await redis_manager.set("test_key", "test_value", ex=1800)
#
#             assert result is True
#             mock_client.set.assert_called_once_with("test_key", "test_value", ex=1800)
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_delete_success(self, redis_manager):
#         """Test successful delete operation."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.delete.return_value = 1
#
#         with patch.object(redis_manager, 'client', mock_client):
#             result = await redis_manager.delete("test_key")
#
#             assert result == 1
#             mock_client.delete.assert_called_once_with("test_key")
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_delete_multiple_keys(self, redis_manager):
#         """Test delete operation with multiple keys."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.delete.return_value = 2
#
#         with patch.object(redis_manager, 'client', mock_client):
#             result = await redis_manager.delete("key1", "key2")
#
#             assert result == 2
#             mock_client.delete.assert_called_once_with("key1", "key2")
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_exists_success(self, redis_manager):
#         """Test successful exists operation."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.exists.return_value = 1
#
#         with patch.object(redis_manager, 'client', mock_client):
#             result = await redis_manager.exists("test_key")
#
#             assert result is True
#             mock_client.exists.assert_called_once_with("test_key")
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_exists_not_found(self, redis_manager):
#         """Test exists operation with non-existent key."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.exists.return_value = 0
#
#         with patch.object(redis_manager, 'client', mock_client):
#             result = await redis_manager.exists("nonexistent_key")
#
#             assert result is False
#             mock_client.exists.assert_called_once_with("nonexistent_key")
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_expire_success(self, redis_manager):
#         """Test successful expire operation."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.expire.return_value = True
#
#         with patch.object(redis_manager, 'client', mock_client):
#             result = await redis_manager.expire("test_key", 3600)
#
#             assert result is True
#             mock_client.expire.assert_called_once_with("test_key", 3600)
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_ttl_success(self, redis_manager):
#         """Test successful TTL operation."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.ttl.return_value = 1800
#
#         with patch.object(redis_manager, 'client', mock_client):
#             result = await redis_manager.ttl("test_key")
#
#             assert result == 1800
#             mock_client.ttl.assert_called_once_with("test_key")
#
#     @pytest.mark.asyncio
#     async def test_redis_manager_context_manager(self, redis_manager):
#         """Test RedisManager as async context manager."""
#         mock_client = AsyncMock(spec=Redis)
#         redis_manager._client = mock_client
#
#         async with redis_manager as manager:
#             assert manager == redis_manager
#
#         mock_client.close.assert_called_once()
#
#
# class TestCreateRedisClient:
#     """Test create_redis_client function."""
#
#     def test_create_redis_client_default_settings(self):
#         """Test Redis client creation with default settings."""
#         redis_url = "redis://localhost:6379/0"
#
#         with patch('app.config.redis.Redis.from_url') as mock_from_url:
#             mock_client = AsyncMock(spec=Redis)
#             mock_from_url.return_value = mock_client
#
#             client = create_redis_client(redis_url)
#
#             assert client == mock_client
#             mock_from_url.assert_called_once_with(
#                 redis_url,
#                 encoding="utf-8",
#                 decode_responses=True,
#                 socket_timeout=5,
#                 socket_connect_timeout=5,
#                 retry_on_timeout=True,
#                 health_check_interval=30
#             )
#
#     def test_create_redis_client_custom_settings(self):
#         """Test Redis client creation with custom settings."""
#         redis_url = "redis://localhost:6379/1"
#
#         with patch('app.config.redis.Redis.from_url') as mock_from_url:
#             mock_client = AsyncMock(spec=Redis)
#             mock_from_url.return_value = mock_client
#
#             client = create_redis_client(
#                 redis_url,
#                 socket_timeout=10,
#                 socket_connect_timeout=10
#             )
#
#             assert client == mock_client
#             mock_from_url.assert_called_once_with(
#                 redis_url,
#                 encoding="utf-8",
#                 decode_responses=True,
#                 socket_timeout=10,
#                 socket_connect_timeout=10,
#                 retry_on_timeout=True,
#                 health_check_interval=30
#             )
#
#     def test_create_redis_client_with_password(self):
#         """Test Redis client creation with password."""
#         redis_url = "redis://:password@localhost:6379/0"
#
#         with patch('app.config.redis.Redis.from_url') as mock_from_url:
#             mock_client = AsyncMock(spec=Redis)
#             mock_from_url.return_value = mock_client
#
#             client = create_redis_client(redis_url)
#
#             assert client == mock_client
#             mock_from_url.assert_called_once()
#             assert mock_from_url.call_args[0][0] == redis_url
#
#     def test_create_redis_client_ssl(self):
#         """Test Redis client creation with SSL."""
#         redis_url = "rediss://localhost:6380/0"
#
#         with patch('app.config.redis.Redis.from_url') as mock_from_url:
#             mock_client = AsyncMock(spec=Redis)
#             mock_from_url.return_value = mock_client
#
#             client = create_redis_client(redis_url)
#
#             assert client == mock_client
#             mock_from_url.assert_called_once()
#             assert mock_from_url.call_args[0][0] == redis_url
#
#
# class TestCheckRedisConnection:
#     """Test check_redis_connection function."""
#
#     @pytest.mark.asyncio
#     async def test_check_redis_connection_success(self):
#         """Test successful Redis connection check."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.ping.return_value = True
#
#         result = await check_redis_connection(mock_client)
#
#         assert result is True
#         mock_client.ping.assert_called_once()
#
#     @pytest.mark.asyncio
#     async def test_check_redis_connection_failure(self):
#         """Test failed Redis connection check."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.ping.side_effect = ConnectionError("Connection failed")
#
#         result = await check_redis_connection(mock_client)
#
#         assert result is False
#
#     @pytest.mark.asyncio
#     async def test_check_redis_connection_timeout(self):
#         """Test Redis connection check with timeout."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.ping.side_effect = TimeoutError("Connection timeout")
#
#         result = await check_redis_connection(mock_client)
#
#         assert result is False
#
#     @pytest.mark.asyncio
#     async def test_check_redis_connection_with_timeout_param(self):
#         """Test Redis connection check with custom timeout."""
#         mock_client = AsyncMock(spec=Redis)
#
#         # Mock a slow ping that times out
#         async def slow_ping():
#             await asyncio.sleep(2)  # Longer than timeout
#             return True
#
#         mock_client.ping.side_effect = slow_ping
#
#         result = await check_redis_connection(mock_client, timeout=1)
#
#         assert result is False
#
#
# class TestInitRedis:
#     """Test init_redis function."""
#
#     @pytest.mark.asyncio
#     async def test_init_redis_success(self):
#         """Test successful Redis initialization."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.ping.return_value = True
#
#         # Should not raise an error
#         await init_redis(mock_client)
#
#         mock_client.ping.assert_called_once()
#
#     @pytest.mark.asyncio
#     async def test_init_redis_failure(self):
#         """Test Redis initialization failure."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.ping.side_effect = RedisError("Initialization failed")
#
#         with pytest.raises(RedisError):
#             await init_redis(mock_client)
#
#
# class TestGetRedisManager:
#     """Test get_redis_manager function."""
#
#     def test_get_redis_manager_returns_instance(self):
#         """Test that get_redis_manager returns RedisManager instance."""
#         with patch('app.config.redis.get_settings') as mock_get_settings:
#             mock_settings = MagicMock(spec=Settings)
#             mock_get_settings.return_value = mock_settings
#
#             manager = get_redis_manager()
#
#             assert isinstance(manager, RedisManager)
#             assert manager.settings == mock_settings
#
#     def test_get_redis_manager_caching(self):
#         """Test that get_redis_manager caches the instance."""
#         with patch('app.config.redis.get_settings') as mock_get_settings:
#             mock_settings = MagicMock(spec=Settings)
#             mock_get_settings.return_value = mock_settings
#
#             # Clear cache first
#             get_redis_manager.cache_clear()
#
#             manager1 = get_redis_manager()
#             manager2 = get_redis_manager()
#
#             # Should return the same instance due to caching
#             assert manager1 is manager2
#
#     def test_get_redis_manager_cache_clear(self):
#         """Test that cache can be cleared."""
#         with patch('app.config.redis.get_settings') as mock_get_settings:
#             mock_settings = MagicMock(spec=Settings)
#             mock_get_settings.return_value = mock_settings
#
#             manager1 = get_redis_manager()
#             get_redis_manager.cache_clear()
#             manager2 = get_redis_manager()
#
#             # Should return different instances after cache clear
#             assert manager1 is not manager2
#
#
# class TestGetRedisClient:
#     """Test get_redis_client function."""
#
#     def test_get_redis_client_returns_client(self):
#         """Test that get_redis_client returns Redis client."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_manager = MagicMock()
#         mock_manager.client = mock_client
#
#         with patch('app.config.redis.get_redis_manager', return_value=mock_manager):
#             client = get_redis_client()
#
#             assert client == mock_client
#
#     def test_get_redis_client_dependency_injection(self):
#         """Test get_redis_client as FastAPI dependency."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_manager = MagicMock()
#         mock_manager.client = mock_client
#
#         with patch('app.config.redis.get_redis_manager', return_value=mock_manager):
#             # Simulate FastAPI dependency injection
#             client = get_redis_client()
#
#             assert client == mock_client
#
#
# class TestRedisIntegration:
#     """Test Redis integration scenarios."""
#
#     @pytest.mark.asyncio
#     async def test_redis_session_lifecycle(self):
#         """Test complete Redis session lifecycle."""
#         mock_settings = MagicMock(spec=Settings)
#         mock_settings.redis_url = "redis://localhost:6379/0"
#         mock_settings.is_testing = False
#
#         manager = RedisManager(mock_settings)
#
#         with patch('app.config.redis.create_redis_client') as mock_create_client:
#             mock_client = AsyncMock(spec=Redis)
#             mock_create_client.return_value = mock_client
#
#             # Get client
#             client = manager.client
#             assert client == mock_client
#
#             # Close manager
#             await manager.close()
#             mock_client.close.assert_called_once()
#
#     @pytest.mark.asyncio
#     async def test_redis_caching_operations(self, redis_manager):
#         """Test Redis caching operations."""
#         mock_client = AsyncMock(spec=Redis)
#
#         # Mock cache operations
#         mock_client.get.return_value = None  # Cache miss
#         mock_client.set.return_value = True
#         mock_client.get.return_value = b"cached_value"  # Cache hit
#
#         with patch.object(redis_manager, 'client', mock_client):
#             # Cache miss
#             result = await redis_manager.get("cache_key")
#             assert result is None
#
#             # Set cache
#             await redis_manager.set("cache_key", "cached_value", ex=3600)
#
#             # Cache hit (would need to mock the second get call differently)
#             mock_client.get.return_value = b"cached_value"
#             result = await redis_manager.get("cache_key")
#             assert result == "cached_value"
#
#     @pytest.mark.asyncio
#     async def test_redis_error_handling(self, redis_manager):
#         """Test Redis error handling scenarios."""
#         mock_client = AsyncMock(spec=Redis)
#         mock_client.get.side_effect = RedisError("Redis error")
#
#         with patch.object(redis_manager, 'client', mock_client):
#             # Should handle Redis errors gracefully
#             with pytest.raises(RedisError):
#                 await redis_manager.get("test_key")
#
#     @pytest.mark.asyncio
#     async def test_redis_connection_retry(self):
#         """Test Redis connection retry logic."""
#         mock_client = AsyncMock(spec=Redis)
#
#         # First attempt fails, second succeeds
#         mock_client.ping.side_effect = [
#             ConnectionError("Connection failed"),
#             True
#         ]
#
#         # This would require implementing retry logic in the actual function
#         # For now, we test that the first attempt fails
#         result = await check_redis_connection(mock_client)
#         assert result is False
#
#     @pytest.mark.asyncio
#     async def test_redis_key_expiration(self, redis_manager):
#         """Test Redis key expiration handling."""
#         mock_client = AsyncMock(spec=Redis)
#
#         # Mock expiration operations
#         mock_client.expire.return_value = True
#         mock_client.ttl.return_value = 1800
#
#         with patch.object(redis_manager, 'client', mock_client):
#             # Set expiration
#             result = await redis_manager.expire("test_key", 3600)
#             assert result is True
#
#             # Check TTL
#             ttl = await redis_manager.ttl("test_key")
#             assert ttl == 1800
#
#
# class TestRedisConfiguration:
#     """Test Redis configuration scenarios."""
#
#     def test_redis_url_parsing(self):
#         """Test Redis URL parsing for different configurations."""
#         test_urls = [
#             "redis://localhost:6379/0",
#             "redis://:password@localhost:6379/1",
#             "rediss://localhost:6380/0",  # SSL
#             "redis://user:pass@redis.example.com:6379/2",
#         ]
#
#         for url in test_urls:
#             with patch('app.config.redis.Redis.from_url') as mock_from_url:
#                 mock_client = AsyncMock(spec=Redis)
#                 mock_from_url.return_value = mock_client
#
#                 client = create_redis_client(url)
#
#                 assert client == mock_client
#                 mock_from_url.assert_called_once()
#                 assert mock_from_url.call_args[0][0] == url
#
#     def test_redis_connection_pool_configuration(self):
#         """Test Redis connection pool configuration."""
#         redis_url = "redis://localhost:6379/0"
#
#         with patch('app.config.redis.Redis.from_url') as mock_from_url:
#             mock_client = AsyncMock(spec=Redis)
#             mock_from_url.return_value = mock_client
#
#             create_redis_client(redis_url)
#
#             call_args = mock_from_url.call_args[1]
#             assert call_args['socket_timeout'] == 5
#             assert call_args['socket_connect_timeout'] == 5
#             assert call_args['retry_on_timeout'] is True
#             assert call_args['health_check_interval'] == 30
#
#     def test_redis_encoding_configuration(self):
#         """Test Redis encoding configuration."""
#         redis_url = "redis://localhost:6379/0"
#
#         with patch('app.config.redis.Redis.from_url') as mock_from_url:
#             mock_client = AsyncMock(spec=Redis)
#             mock_from_url.return_value = mock_client
#
#             create_redis_client(redis_url)
#
#             call_args = mock_from_url.call_args[1]
#             assert call_args['encoding'] == "utf-8"
#             assert call_args['decode_responses'] is True
#
#     def test_redis_testing_configuration(self):
#         """Test Redis configuration for testing."""
#         mock_settings = MagicMock(spec=Settings)
#         mock_settings.redis_url = "redis://localhost:6379/15"  # Test database
#         mock_settings.is_testing = True
#
#         manager = RedisManager(mock_settings)
#
#         with patch('app.config.redis.create_redis_client') as mock_create_client:
#             mock_client = AsyncMock(spec=Redis)
#             mock_create_client.return_value = mock_client
#
#             client = manager.client
#
#             assert client == mock_client
#             mock_create_client.assert_called_once_with(mock_settings.redis_url)
#
#     def test_redis_production_configuration(self):
#         """Test Redis configuration for production."""
#         mock_settings = MagicMock(spec=Settings)
#         mock_settings.redis_url = "rediss://redis.production.com:6380/0"
#         mock_settings.is_testing = False
#
#         manager = RedisManager(mock_settings)
#
#         with patch('app.config.redis.create_redis_client') as mock_create_client:
#             mock_client = AsyncMock(spec=Redis)
#             mock_create_client.return_value = mock_client
#
#             client = manager.client
#
#             assert client == mock_client
#             mock_create_client.assert_called_once_with(mock_settings.redis_url)