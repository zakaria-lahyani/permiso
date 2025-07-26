"""Redis configuration and connection management using redis[async]."""

import json
from typing import Any, Optional
from functools import lru_cache

import redis.asyncio as redis
from redis.asyncio import Redis

from app.config.settings import settings, get_settings


class RedisClient:
    """Redis client wrapper with connection management."""

    def __init__(self):
        self._redis: Optional[Redis] = None

    async def connect(self) -> None:
        """Establish Redis connection."""
        self._redis = redis.from_url(
            settings.REDIS_URL,
            password=settings.REDIS_PASSWORD,
            decode_responses=settings.REDIS_DECODE_RESPONSES,
            retry_on_timeout=True,
            socket_keepalive=True,
            socket_keepalive_options={},
        )

    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.aclose()

    @property
    def redis(self) -> Redis:
        """Get Redis instance."""
        if not self._redis:
            raise RuntimeError("Redis not connected. Call connect() first.")
        return self._redis

    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from Redis.
        
        Args:
            key: Redis key
            
        Returns:
            Deserialized value or None if key doesn't exist
        """
        value = await self.redis.get(key)
        if value is None:
            return None
        
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value

    async def set(
        self,
        key: str,
        value: Any,
        expire: Optional[int] = None,
        nx: bool = False,
        xx: bool = False,
    ) -> bool:
        """
        Set value in Redis.
        
        Args:
            key: Redis key
            value: Value to store
            expire: Expiration time in seconds
            nx: Only set if key doesn't exist
            xx: Only set if key exists
            
        Returns:
            True if operation was successful
        """
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        
        return await self.redis.set(key, value, ex=expire, nx=nx, xx=xx)

    async def delete(self, *keys: str) -> int:
        """
        Delete keys from Redis.
        
        Args:
            keys: Keys to delete
            
        Returns:
            Number of keys deleted
        """
        return await self.redis.delete(*keys)

    async def exists(self, key: str) -> bool:
        """
        Check if key exists in Redis.
        
        Args:
            key: Redis key
            
        Returns:
            True if key exists
        """
        return bool(await self.redis.exists(key))

    async def expire(self, key: str, seconds: int) -> bool:
        """
        Set expiration time for key.
        
        Args:
            key: Redis key
            seconds: Expiration time in seconds
            
        Returns:
            True if expiration was set
        """
        return await self.redis.expire(key, seconds)

    async def ttl(self, key: str) -> int:
        """
        Get time to live for key.
        
        Args:
            key: Redis key
            
        Returns:
            TTL in seconds, -1 if no expiration, -2 if key doesn't exist
        """
        return await self.redis.ttl(key)

    async def incr(self, key: str, amount: int = 1) -> int:
        """
        Increment key value.
        
        Args:
            key: Redis key
            amount: Amount to increment
            
        Returns:
            New value after increment
        """
        return await self.redis.incr(key, amount)

    async def decr(self, key: str, amount: int = 1) -> int:
        """
        Decrement key value.
        
        Args:
            key: Redis key
            amount: Amount to decrement
            
        Returns:
            New value after decrement
        """
        return await self.redis.decr(key, amount)

    async def sadd(self, key: str, *values: Any) -> int:
        """
        Add values to set.
        
        Args:
            key: Redis key
            values: Values to add
            
        Returns:
            Number of values added
        """
        return await self.redis.sadd(key, *values)

    async def srem(self, key: str, *values: Any) -> int:
        """
        Remove values from set.
        
        Args:
            key: Redis key
            values: Values to remove
            
        Returns:
            Number of values removed
        """
        return await self.redis.srem(key, *values)

    async def sismember(self, key: str, value: Any) -> bool:
        """
        Check if value is member of set.
        
        Args:
            key: Redis key
            value: Value to check
            
        Returns:
            True if value is in set
        """
        return await self.redis.sismember(key, value)

    async def smembers(self, key: str) -> set:
        """
        Get all members of set.
        
        Args:
            key: Redis key
            
        Returns:
            Set of all members
        """
        return await self.redis.smembers(key)

    async def ping(self) -> bool:
        """
        Ping Redis server.
        
        Returns:
            True if server responds
        """
        try:
            response = await self.redis.ping()
            return response == b"PONG" or response == "PONG"
        except Exception:
            return False

    async def flushdb(self) -> bool:
        """
        Flush current database.
        
        Returns:
            True if operation was successful
        """
        try:
            await self.redis.flushdb()
            return True
        except Exception:
            return False

    async def keys(self, pattern: str = "*") -> list[str]:
        """
        Get keys matching pattern.
        
        Args:
            pattern: Key pattern to match
            
        Returns:
            List of matching keys
        """
        return await self.redis.keys(pattern)

    async def scan_iter(self, match: str = "*", count: int = 1000):
        """
        Iterate over keys matching pattern.
        
        Args:
            match: Key pattern to match
            count: Number of keys to return per iteration
            
        Yields:
            Matching keys
        """
        async for key in self.redis.scan_iter(match=match, count=count):
            yield key

    async def pipeline(self):
        """
        Create Redis pipeline for batch operations.
        
        Returns:
            Redis pipeline instance
        """
        return self.redis.pipeline()

    async def execute_pipeline(self, pipe) -> list:
        """
        Execute Redis pipeline.
        
        Args:
            pipe: Redis pipeline instance
            
        Returns:
            List of results from pipeline operations
        """
        return await pipe.execute()


# Global Redis client instance
redis_client = RedisClient()


class RedisManager:
    """Redis manager with additional functionality."""
    
    def __init__(self, settings=None):
        if settings:
            self.client = redis.from_url(
                settings.redis_url,
                decode_responses=True,
                retry_on_timeout=True,
                socket_keepalive=True,
            )
        else:
            from app.config.settings import settings as app_settings
            self.client = redis.from_url(
                app_settings.REDIS_URL,
                decode_responses=True,
                retry_on_timeout=True,
                socket_keepalive=True,
            )
    
    async def set(self, key: str, value: Any, ex: Optional[int] = None) -> bool:
        """Set a key-value pair."""
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        return await self.client.set(key, value, ex=ex)
    
    async def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        value = await self.client.get(key)
        if value is None:
            return None
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
    
    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        return bool(await self.client.exists(key))
    
    async def delete(self, *keys: str) -> int:
        """Delete keys."""
        return await self.client.delete(*keys)
    
    async def ttl(self, key: str) -> int:
        """Get TTL for key."""
        return await self.client.ttl(key)
    
    async def health_check(self) -> bool:
        """Check Redis health."""
        try:
            return await self.client.ping()
        except Exception:
            return False
    
    async def close(self):
        """Close Redis connection."""
        await self.client.aclose()
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()


def create_redis_client(redis_url: str):
    """Create a Redis client with the given URL."""
    return redis.from_url(
        redis_url,
        decode_responses=True,
        retry_on_timeout=True,
        socket_keepalive=True,
    )


@lru_cache()
def get_redis_manager() -> RedisManager:
    """Get Redis manager instance."""
    return RedisManager()


async def get_redis() -> RedisClient:
    """
    Dependency function to get Redis client.
    
    Returns:
        RedisClient: Redis client instance
    """
    return redis_client


async def init_redis() -> None:
    """Initialize Redis connection."""
    await redis_client.connect()


async def close_redis() -> None:
    """Close Redis connection."""
    await redis_client.disconnect()