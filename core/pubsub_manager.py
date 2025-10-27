import asyncio
import json
from core.logger import log
from core.redis_client import get_redis_client

class PubSubManager:
    def __init__(self):
        self.redis = None
        self.pubsub = None
        self.listeners = {} # {channel: [callback1, callback2]}
        self.listener_task = None
        self.use_redis = False
        self._memory_messages = [] # In-memory fallback

    async def setup(self):
        try:
            self.redis = await get_redis_client()
            self.pubsub = self.redis.pubsub()
            self.use_redis = True
            log.success("PubSubManager: Using Redis backend")
        except Exception as e:
            log.warning(f"PubSubManager: Redis unavailable, using in-memory fallback: {e}")
            self.use_redis = False
            self.redis = None
            self.pubsub = None

    async def publish(self, channel: str, message: dict):
        """Publishes a message to a given channel."""
        if self.use_redis and self.redis:
            try:
                await self.redis.publish(channel, json.dumps(message))
                log.debug(f"Published to channel '{channel}': {message}")
            except Exception as e:
                log.error(f"Failed to publish to channel '{channel}': {e}")
        else:
            # In-memory fallback - just call callbacks directly
            log.debug(f"Published to in-memory channel '{channel}': {message}")
            if channel in self.listeners:
                for callback in self.listeners[channel]:
                    asyncio.create_task(callback(message))

    async def subscribe(self, channel: str, callback):
        """Subscribes a callback function to a channel."""
        if channel not in self.listeners:
            self.listeners[channel] = []
            
            if self.use_redis and self.pubsub:
                await self.pubsub.subscribe(channel)
                log.info(f"Subscribed to Redis channel '{channel}'.")
                # Start the listener task if not already running
                if not self.listener_task or self.listener_task.done():
                    self.listener_task = asyncio.create_task(self._listen_for_messages())
            else:
                log.info(f"Subscribed to in-memory channel '{channel}'.")
        
        self.listeners[channel].append(callback)
        log.debug(f"Added callback for channel '{channel}'.")

    async def unsubscribe(self, channel: str, callback):
        """Unsubscribes a callback function from a channel."""
        if channel in self.listeners:
            if callback in self.listeners[channel]:
                self.listeners[channel].remove(callback)
                log.debug(f"Removed callback for channel '{channel}'.")
            if not self.listeners[channel]:
                if self.use_redis and self.pubsub:
                    await self.pubsub.unsubscribe(channel)
                del self.listeners[channel]
                log.info(f"Unsubscribed from channel '{channel}'.")
                # If no more listeners, stop the listener task
                if not self.listeners and self.listener_task and not self.listener_task.done():
                    self.listener_task.cancel()
                    self.listener_task = None

    async def _listen_for_messages(self):
        """Listens for messages on subscribed channels and dispatches them to callbacks."""
        if not self.use_redis or not self.pubsub:
            return
        
        try:
            while True:
                message = await self.pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message['type'] == 'message':
                    log.debug(f"Received message: {message}")
                    channel = message['channel'].decode('utf-8')
                    data = message['data']
                    log.debug(f"Message data type: {type(data)}")
                    log.debug(f"Message data value: {data}")
                    data = json.loads(message['data'])
                    log.debug(f"Received message on channel '{channel}': {data}")
                    
                    if channel in self.listeners:
                        for callback in self.listeners[channel]:
                            # Run callbacks in a non-blocking way
                            asyncio.create_task(callback(data))
                await asyncio.sleep(0.01) # Prevent busy-waiting
        except asyncio.CancelledError:
            log.info("PubSub listener task cancelled.")
        except Exception as e:
            log.error(f"Error in PubSub listener: {e}")
        finally:
            if self.pubsub:
                await self.pubsub.close()
            log.info("PubSub listener stopped.")

    async def close(self):
        """Closes the PubSubManager and its connections."""
        if self.listener_task and not self.listener_task.done():
            self.listener_task.cancel()
            try:
                await self.listener_task
            except asyncio.CancelledError:
                pass
        if self.pubsub:
            await self.pubsub.close()
        if self.redis:
            await self.redis.close()
        log.info("PubSubManager closed.")

