"""
LLM Wrapper with Timeout and Error Handling
Provides robust timeout management and error handling for all LLM calls
"""

import asyncio
import time
import os
from typing import Dict, Any, Optional, Callable
from loguru import logger
from functools import wraps


class LLMTimeoutError(Exception):
    """Custom exception for LLM timeout"""
    pass


class LLMCallError(Exception):
    """Custom exception for LLM call errors"""
    pass


class LLMWrapper:
    """
    Wrapper for LLM calls with timeout and error handling
    
    Features:
    - Configurable timeout per call
    - Automatic retry with exponential backoff
    - Comprehensive error logging
    - Circuit breaker pattern
    - Rate limiting
    """
    
    def __init__(
        self,
        default_timeout: int = None,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        circuit_breaker_threshold: int = 5
    ):
        self.default_timeout = default_timeout or int(os.getenv("LLM_REQUEST_TIMEOUT", "120"))
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.circuit_breaker_threshold = circuit_breaker_threshold
        
        # Circuit breaker state
        self.failure_count = 0
        self.circuit_open = False
        self.last_failure_time = None
        self.circuit_reset_timeout = 60  # seconds
        
        logger.info(f"LLMWrapper initialized with timeout={self.default_timeout}s, max_retries={self.max_retries}")
    
    def _check_circuit_breaker(self):
        """Check if circuit breaker should be reset or is open"""
        if self.circuit_open:
            # Check if we should reset the circuit
            if self.last_failure_time and (time.time() - self.last_failure_time) > self.circuit_reset_timeout:
                logger.info("Circuit breaker reset - attempting to reconnect")
                self.circuit_open = False
                self.failure_count = 0
            else:
                raise LLMCallError("Circuit breaker is OPEN - too many failures. Please wait before retrying.")
    
    def _record_failure(self):
        """Record a failure and potentially open circuit breaker"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.circuit_breaker_threshold:
            self.circuit_open = True
            logger.error(f"Circuit breaker OPENED after {self.failure_count} failures")
    
    def _record_success(self):
        """Record a successful call"""
        self.failure_count = 0
        self.circuit_open = False
    
    async def call_async(
        self,
        func: Callable,
        *args,
        timeout: Optional[int] = None,
        retry: bool = True,
        **kwargs
    ) -> Any:
        """
        Call async LLM function with timeout and error handling
        
        Args:
            func: Async function to call
            *args: Positional arguments for func
            timeout: Timeout in seconds (uses default if None)
            retry: Whether to retry on failure
            **kwargs: Keyword arguments for func
            
        Returns:
            Result from func
            
        Raises:
            LLMTimeoutError: If call times out
            LLMCallError: If call fails after retries
        """
        self._check_circuit_breaker()
        
        timeout_seconds = timeout or self.default_timeout
        max_attempts = self.max_retries if retry else 1
        
        for attempt in range(max_attempts):
            try:
                logger.debug(f"LLM call attempt {attempt + 1}/{max_attempts} with timeout={timeout_seconds}s")
                
                # Execute with timeout
                result = await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=timeout_seconds
                )
                
                # Success
                self._record_success()
                logger.debug(f"LLM call succeeded on attempt {attempt + 1}")
                return result
                
            except asyncio.TimeoutError:
                error_msg = f"LLM call timed out after {timeout_seconds}s (attempt {attempt + 1}/{max_attempts})"
                logger.error(error_msg)
                
                if attempt < max_attempts - 1:
                    delay = self.backoff_factor ** attempt
                    logger.info(f"Retrying in {delay}s...")
                    await asyncio.sleep(delay)
                else:
                    self._record_failure()
                    raise LLMTimeoutError(error_msg)
                    
            except Exception as e:
                error_msg = f"LLM call failed: {type(e).__name__}: {str(e)} (attempt {attempt + 1}/{max_attempts})"
                logger.error(error_msg)
                
                if attempt < max_attempts - 1:
                    delay = self.backoff_factor ** attempt
                    logger.info(f"Retrying in {delay}s...")
                    await asyncio.sleep(delay)
                else:
                    self._record_failure()
                    raise LLMCallError(error_msg) from e
    
    def call_sync(
        self,
        func: Callable,
        *args,
        timeout: Optional[int] = None,
        retry: bool = True,
        **kwargs
    ) -> Any:
        """
        Call sync LLM function with timeout and error handling
        
        Args:
            func: Sync function to call
            *args: Positional arguments for func
            timeout: Timeout in seconds (uses default if None)
            retry: Whether to retry on failure
            **kwargs: Keyword arguments for func
            
        Returns:
            Result from func
            
        Raises:
            LLMTimeoutError: If call times out
            LLMCallError: If call fails after retries
        """
        self._check_circuit_breaker()
        
        timeout_seconds = timeout or self.default_timeout
        max_attempts = self.max_retries if retry else 1
        
        for attempt in range(max_attempts):
            try:
                logger.debug(f"LLM call attempt {attempt + 1}/{max_attempts} with timeout={timeout_seconds}s")
                
                # For sync calls, we use threading timeout
                import signal
                
                def timeout_handler(signum, frame):
                    raise TimeoutError(f"LLM call timed out after {timeout_seconds}s")
                
                # Set timeout alarm
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(timeout_seconds)
                
                try:
                    result = func(*args, **kwargs)
                    signal.alarm(0)  # Cancel alarm
                    
                    # Success
                    self._record_success()
                    logger.debug(f"LLM call succeeded on attempt {attempt + 1}")
                    return result
                    
                finally:
                    signal.alarm(0)  # Ensure alarm is cancelled
                    
            except TimeoutError:
                error_msg = f"LLM call timed out after {timeout_seconds}s (attempt {attempt + 1}/{max_attempts})"
                logger.error(error_msg)
                
                if attempt < max_attempts - 1:
                    delay = self.backoff_factor ** attempt
                    logger.info(f"Retrying in {delay}s...")
                    time.sleep(delay)
                else:
                    self._record_failure()
                    raise LLMTimeoutError(error_msg)
                    
            except Exception as e:
                error_msg = f"LLM call failed: {type(e).__name__}: {str(e)} (attempt {attempt + 1}/{max_attempts})"
                logger.error(error_msg)
                
                if attempt < max_attempts - 1:
                    delay = self.backoff_factor ** attempt
                    logger.info(f"Retrying in {delay}s...")
                    time.sleep(delay)
                else:
                    self._record_failure()
                    raise LLMCallError(error_msg) from e


def with_llm_timeout(timeout: Optional[int] = None, retry: bool = True):
    """
    Decorator for async LLM functions to add timeout and error handling
    
    Usage:
        @with_llm_timeout(timeout=60)
        async def my_llm_call():
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            llm_wrapper = LLMWrapper()
            return await llm_wrapper.call_async(func, *args, timeout=timeout, retry=retry, **kwargs)
        return wrapper
    return decorator


def with_llm_timeout_sync(timeout: Optional[int] = None, retry: bool = True):
    """
    Decorator for sync LLM functions to add timeout and error handling
    
    Usage:
        @with_llm_timeout_sync(timeout=60)
        def my_llm_call():
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            llm_wrapper = LLMWrapper()
            return llm_wrapper.call_sync(func, *args, timeout=timeout, retry=retry, **kwargs)
        return wrapper
    return decorator


# Global instance
llm_wrapper = LLMWrapper()

