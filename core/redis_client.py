
import redis.asyncio as aioredis # Use redis.asyncio as aioredis
from redis import exceptions as redis_exceptions # Import redis exceptions
from config import settings
from core.logger import log

_redis_client_instance = None

async def get_redis_client(): # Make this function async
    global _redis_client_instance
    if _redis_client_instance is None:
        try:
            # Create a connection pool
            pool = aioredis.ConnectionPool.from_url(
                f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}",
                max_connections=50, # Adjust based on expected concurrency
                decode_responses=True
            )
            # Create the client instance from the pool
            _redis_client_instance = await aioredis.Redis(connection_pool=pool)
            await _redis_client_instance.ping()  # Check the connection
            log.info("Successfully connected to Redis (aioredis).")
        except redis_exceptions.ConnectionError as e: # Catch redis_exceptions.ConnectionError
            log.critical(
                f"Could not connect to Redis at {settings.REDIS_HOST}:{settings.REDIS_PORT}. Please ensure Redis is running. Error: {e}")
            _redis_client_instance = None # Ensure it's None on failure
            raise ConnectionError(f"Failed to connect to Redis: {e}") # Re-raise for CacheManager to catch
    return _redis_client_instance
