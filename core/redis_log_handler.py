# core/redis_log_handler.py

import logging
import redis
from config import settings


class RedisLogHandler(logging.Handler):
    """A logging handler that publishes log records to a Redis channel."""

    def __init__(self, channel="dlnk_logs"):
        super().__init__()
        self.channel = channel
        try:
            # Use a separate Redis connection for the handler
            self.redis_client = redis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                decode_responses=True
            )
            self.redis_client.ping()
            self.enabled = True
        except redis.exceptions.ConnectionError:
            self.enabled = False
            # We don't log here to avoid a recursive loop if Redis is down
            print(
                "WARNING: RedisLogHandler could not connect to Redis. Real-time logging will be disabled.")

    def emit(self, record):
        """Publish a log record to the Redis channel."""
        if not self.enabled:
            return

        try:
            # We format the message here before sending
            log_entry = self.format(record)
            self.redis_client.publish(self.channel, log_entry)
        except Exception:
            # Again, avoid logging from within the handler itself
            pass
