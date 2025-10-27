import os
import redis.asyncio as redis
import json
from dotenv import load_dotenv
import asyncio

# Load environment variables from .env file
load_dotenv()

# Get Redis connection details from environment variables
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

class RedisManager:
    """A manager for handling Redis connections and operations."""
    _pool = None

    @classmethod
    async def get_pool(cls):
        """Initializes and returns the Redis connection pool."""
        if cls._pool is None:
            print("Initializing Redis connection pool...")
            cls._pool = redis.ConnectionPool.from_url(REDIS_URL, decode_responses=True)
            print("Redis connection pool initialized.")
        return cls._pool

    @classmethod
    async def get_connection(cls):
        """Gets a single Redis connection from the pool."""
        pool = await cls.get_pool()
        return redis.Redis(connection_pool=pool)

    @classmethod
    async def close_pool(cls):
        """Closes the Redis connection pool."""
        if cls._pool:
            print("Closing Redis connection pool...")
            await cls._pool.disconnect()
            cls._pool = None
            print("Redis connection pool closed.")

async def set_cache(key: str, value, ttl: int = 3600):
    """Sets a value in the Redis cache with a TTL."""
    try:
        r = await RedisManager.get_connection()
        await r.set(key, json.dumps(value), ex=ttl)
    except Exception as e:
        print(f"Error setting cache for key '{key}': {e}")

async def get_cache(key: str):
    """Gets a value from the Redis cache."""
    try:
        r = await RedisManager.get_connection()
        cached_value = await r.get(key)
        if cached_value:
            return json.loads(cached_value)
        return None
    except Exception as e:
        print(f"Error getting cache for key '{key}': {e}")
        return None

async def clear_cache(key: str):
    """Clears a specific key from the Redis cache."""
    try:
        r = await RedisManager.get_connection()
        await r.delete(key)
    except Exception as e:
        print(f"Error clearing cache for key '{key}': {e}")

# Example usage:
async def main():
    print("Testing Redis connection...")
    await set_cache("test_key", {"message": "Hello, Redis!"})
    print("Set test key.")
    value = await get_cache("test_key")
    print(f"Got value: {value}")
    await clear_cache("test_key")
    print("Cleared test key.")
    await RedisManager.close_pool()

if __name__ == "__main__":
    asyncio.run(main())
