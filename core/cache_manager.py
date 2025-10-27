import json
from typing import Any, Optional
from core.logger import log
from core.redis_client import get_redis_client # Import the new function

class CacheManager:
    def __init__(self):
        self.redis = None # Initialize to None
        self.prefix = "cache:"

    async def setup(self):
        """Asynchronously sets up the Redis client connection."""
        try:
            self.redis = await get_redis_client() # Await the async function
        except ConnectionError as e:
            log.critical("Redis client is not available. CacheManager cannot function.")
            raise e

    async def get(self, key: str) -> Optional[Any]:
        """Retrieves a value from the cache."""
        if not self.redis:
            log.error("Redis client not initialized in CacheManager.")
            return None
        try:
            cached_value = await self.redis.get(f"{self.prefix}{key}") # Await Redis operation
            if cached_value:
                log.debug(f"Cache hit for key: {key}")
                return json.loads(cached_value)
            log.debug(f"Cache miss for key: {key}")
            return None
        except Exception as e:
            log.error(f"Error retrieving from cache for key {key}: {e}")
            return None

    async def set(self, key: str, value: Any, ttl: int = 3600):
        """Stores a value in the cache with an optional time-to-live (TTL) in seconds."""
        if not self.redis:
            log.error("Redis client not initialized in CacheManager.")
            return
        try:
            await self.redis.setex(f"{self.prefix}{key}", ttl, json.dumps(value)) # Await Redis operation
            log.debug(f"Cache set for key: {key} with TTL: {ttl}s")
        except Exception as e:
            log.error(f"Error setting cache for key {key}: {e}")

    async def delete(self, key: str):
        """Deletes a value from the cache."""
        if not self.redis:
            log.error("Redis client not initialized in CacheManager.")
            return
        try:
            await self.redis.delete(f"{self.prefix}{key}") # Await Redis operation
            log.debug(f"Cache deleted for key: {key}")
        except Exception as e:
            log.error(f"Error deleting cache for key {key}: {e}")

    async def clear_prefix(self, prefix: str):
        """Deletes all keys with a given prefix."""
        if not self.redis:
            log.error("Redis client not initialized in CacheManager.")
            return
        try:
            # aioredis scan_iter is async
            async for key in self.redis.scan_iter(f"{self.prefix}{prefix}*"):
                await self.redis.delete(key) # Await Redis operation
            log.debug(f"Cache cleared for prefix: {prefix}")
        except Exception as e:
            log.error(f"Error clearing cache for prefix {prefix}: {e}")
