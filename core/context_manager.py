import json
from typing import Any, Dict, Optional
import asyncio
from core.logger import log
from core.redis_client import get_redis_client # Use the new lazy-initialized client

class ContextManager:
    """
    Manages shared context data using Redis or in-memory fallback.
    Provides concurrency control and real-time updates.
    """
    def __init__(self, context_key: str = "global_context"):
        self.context_key = context_key
        self.redis = None # Initialize to None
        self.use_redis = False
        self._memory_context = {} # In-memory fallback

    async def setup(self):
        """Asynchronously sets up the Redis client connection with fallback."""
        try:
            self.redis = await get_redis_client()
            self.use_redis = True
            log.success("ContextManager: Using Redis backend")
        except ConnectionError as e:
            log.warning(f"ContextManager: Redis unavailable, using in-memory fallback: {e}")
            self.use_redis = False
            self.redis = None

    async def get_context(self, field: Optional[str] = None) -> Any:
        """
        Retrieves the entire context or a specific field.
        """
        try:
            if self.use_redis and self.redis:
                if field:
                    value = await self.redis.hget(self.context_key, field)
                    if value is None:
                        return None
                    if isinstance(value, bytes):
                        value = value.decode('utf-8')
                    return json.loads(value)
                else:
                    full_context = await self.redis.hgetall(self.context_key)
                    return {(k.decode('utf-8') if isinstance(k, bytes) else k): json.loads(v.decode('utf-8') if isinstance(v, bytes) else v) for k, v in full_context.items()}
            else:
                # In-memory fallback
                if field:
                    return self._memory_context.get(field)
                else:
                    return self._memory_context.copy()
        except Exception as e:
            log.error(f"Error getting context (field: {field}): {e}")
            # Fallback to memory on error
            if field:
                return self._memory_context.get(field)
            return self._memory_context.copy()

    async def set_context(self, field: str, value: Any):
        """
        Sets a specific field in the context with a new value.
        """
        try:
            if self.use_redis and self.redis:
                await self.redis.hset(self.context_key, field, json.dumps(value))
                log.debug(f"Context field '{field}' set in Redis.")
            else:
                # In-memory fallback
                self._memory_context[field] = value
                log.debug(f"Context field '{field}' set in memory.")
        except Exception as e:
            log.error(f"Error setting context (field: {field}): {e}")
            # Fallback to memory on error
            self._memory_context[field] = value

    async def update_context(self, updates: Dict[str, Any]):
        """
        Updates multiple fields in the context.
        """
        try:
            if self.use_redis and self.redis:
                # Use a mapping dictionary for hmset
                mapping = {field: json.dumps(value) for field, value in updates.items()}
                await self.redis.hmset(self.context_key, mapping)
                log.debug(f"Context updated with fields: {list(updates.keys())}")
            else:
                # In-memory fallback
                self._memory_context.update(updates)
                log.debug(f"Context updated in memory with fields: {list(updates.keys())}")
        except Exception as e:
            log.error(f"Error updating context: {e}")
            # Fallback to memory on error
            self._memory_context.update(updates)

    async def delete_context_field(self, field: str):
        """
        Deletes a specific field from the context.
        """
        try:
            if self.use_redis and self.redis:
                await self.redis.hdel(self.context_key, field)
                log.debug(f"Context field '{field}' deleted from Redis.")
            else:
                # In-memory fallback
                self._memory_context.pop(field, None)
                log.debug(f"Context field '{field}' deleted from memory.")
        except Exception as e:
            log.error(f"Error deleting context field '{field}': {e}")
            # Fallback to memory on error
            self._memory_context.pop(field, None)

    async def clear_context(self):
        """
        Clears all fields from the context.
        """
        try:
            if self.use_redis and self.redis:
                await self.redis.delete(self.context_key)
                log.debug(f"Context '{self.context_key}' cleared from Redis.")
            else:
                # In-memory fallback
                self._memory_context.clear()
                log.debug(f"Context cleared from memory.")
        except Exception as e:
            log.error(f"Error clearing context '{self.context_key}': {e}")
            # Fallback to memory on error
            self._memory_context.clear()

    # --- Event Publishing/Subscription (Optional, for real-time notifications) ---
    async def publish_event(self, channel: str, message: Dict[str, Any]):
        """
        Publishes a message to a Redis Pub/Sub channel.
        Only works with Redis backend.
        """
        if not self.use_redis or not self.redis:
            log.debug(f"Publish event skipped (no Redis): channel '{channel}'")
            return
        
        try:
            await self.redis.publish(channel, json.dumps(message))
            log.debug(f"Published event to channel '{channel}'.")
        except Exception as e:
            log.error(f"Error publishing event to channel '{channel}': {e}")

    async def subscribe_to_channel(self, channel: str, handler_func):
        """
        Subscribes to a Redis Pub/Sub channel and calls handler_func for each message.
        Only works with Redis backend.
        Note: This is a blocking operation for the current coroutine.
        """
        if not self.use_redis or not self.redis:
            log.warning(f"Subscribe skipped (no Redis): channel '{channel}'")
            return
        
        try:
            pubsub = self.redis.pubsub()
            await pubsub.subscribe(channel)
            log.info(f"Subscribed to Redis channel '{channel}'.")
            async for message in pubsub.listen():
                if message['type'] == 'message':
                    data = json.loads(message['data'])
                    await handler_func(data)
        except Exception as e:
            log.error(f"Error subscribing to channel '{channel}': {e}")


    async def cleanup(self):
        """
        Cleanup resources
        """
        log.debug("ContextManager cleanup called")
        if not self.use_redis:
            self._memory_context.clear()

