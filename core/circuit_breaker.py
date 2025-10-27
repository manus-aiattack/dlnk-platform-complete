import time
from enum import Enum
import asyncio

class CircuitBreakerState(Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

class CircuitBreakerError(Exception):
    def __init__(self, message, remaining_time):
        self.message = message
        self.remaining_time = remaining_time
        super().__init__(f"{message} - Try again in {remaining_time:.2f} seconds.")

class CircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_timeout=30, name=""):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.name = name
        self.failure_count = 0
        self.state = CircuitBreakerState.CLOSED
        self.last_failure_time = None

    async def execute(self, func, *args, **kwargs):
        if self.state == CircuitBreakerState.OPEN:
            remaining_time = self.recovery_timeout - (time.time() - self.last_failure_time)
            if remaining_time <= 0:
                self.state = CircuitBreakerState.HALF_OPEN
            else:
                raise CircuitBreakerError(f"Circuit for '{self.name}' is open.", remaining_time)

        if self.state == CircuitBreakerState.HALF_OPEN:
            try:
                result = await func(*args, **kwargs)
                self.reset()
                return result
            except Exception as e:
                self.trip()
                raise e

        # state is CLOSED
        try:
            result = await func(*args, **kwargs)
            self.reset() # Reset on success
            return result
        except Exception as e:
            self.record_failure()
            raise e

    def record_failure(self):
        self.failure_count += 1
        if self.failure_count >= self.failure_threshold:
            self.trip()

    def trip(self):
        self.state = CircuitBreakerState.OPEN
        self.last_failure_time = time.time()
        self.failure_count = self.failure_threshold 

    def reset(self):
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None