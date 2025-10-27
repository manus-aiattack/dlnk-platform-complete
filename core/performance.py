"""
Performance Optimization Utilities
เพิ่มประสิทธิภาพการทำงานของระบบ
"""

import asyncio
import time
import functools
from typing import Callable, Any, Dict, Optional
from loguru import logger


class PerformanceMonitor:
    """
    Monitor และ track performance ของฟังก์ชัน
    """
    
    def __init__(self):
        self.metrics = {}
    
    def record(self, func_name: str, duration: float, success: bool = True):
        """Record performance metric"""
        if func_name not in self.metrics:
            self.metrics[func_name] = {
                "calls": 0,
                "total_time": 0,
                "avg_time": 0,
                "min_time": float('inf'),
                "max_time": 0,
                "successes": 0,
                "failures": 0
            }
        
        metric = self.metrics[func_name]
        metric["calls"] += 1
        metric["total_time"] += duration
        metric["avg_time"] = metric["total_time"] / metric["calls"]
        metric["min_time"] = min(metric["min_time"], duration)
        metric["max_time"] = max(metric["max_time"], duration)
        
        if success:
            metric["successes"] += 1
        else:
            metric["failures"] += 1
    
    def get_metrics(self, func_name: Optional[str] = None) -> Dict[str, Any]:
        """Get performance metrics"""
        if func_name:
            return self.metrics.get(func_name, {})
        return self.metrics
    
    def print_summary(self):
        """Print performance summary"""
        logger.info("=" * 80)
        logger.info("PERFORMANCE SUMMARY")
        logger.info("=" * 80)
        
        for func_name, metric in sorted(self.metrics.items(), key=lambda x: x[1]["total_time"], reverse=True):
            logger.info(f"\n{func_name}:")
            logger.info(f"  Calls: {metric['calls']}")
            logger.info(f"  Total Time: {metric['total_time']:.2f}s")
            logger.info(f"  Avg Time: {metric['avg_time']:.2f}s")
            logger.info(f"  Min Time: {metric['min_time']:.2f}s")
            logger.info(f"  Max Time: {metric['max_time']:.2f}s")
            logger.info(f"  Success Rate: {metric['successes']}/{metric['calls']} ({metric['successes']/metric['calls']*100:.1f}%)")


# Global performance monitor
perf_monitor = PerformanceMonitor()


def measure_performance(func: Callable) -> Callable:
    """
    Decorator to measure function performance
    
    Usage:
        @measure_performance
        async def my_function():
            ...
    """
    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs) -> Any:
        start_time = time.time()
        success = True
        
        try:
            result = await func(*args, **kwargs)
            return result
        except Exception as e:
            success = False
            raise
        finally:
            duration = time.time() - start_time
            perf_monitor.record(func.__name__, duration, success)
            
            if duration > 5:  # Log slow operations
                logger.warning(f"{func.__name__}() took {duration:.2f}s")
    
    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs) -> Any:
        start_time = time.time()
        success = True
        
        try:
            result = func(*args, **kwargs)
            return result
        except Exception as e:
            success = False
            raise
        finally:
            duration = time.time() - start_time
            perf_monitor.record(func.__name__, duration, success)
            
            if duration > 5:  # Log slow operations
                logger.warning(f"{func.__name__}() took {duration:.2f}s")
    
    # Return appropriate wrapper
    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper


def cache_result(ttl: int = 300):
    """
    Cache function results with TTL
    
    Args:
        ttl: Time to live in seconds (default: 300)
    
    Usage:
        @cache_result(ttl=60)
        async def expensive_operation():
            ...
    """
    cache = {}
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            # Create cache key
            cache_key = f"{func.__name__}:{str(args)}:{str(kwargs)}"
            
            # Check cache
            if cache_key in cache:
                cached_value, cached_time = cache[cache_key]
                if time.time() - cached_time < ttl:
                    logger.debug(f"Cache hit for {func.__name__}")
                    return cached_value
            
            # Execute function
            result = await func(*args, **kwargs)
            
            # Store in cache
            cache[cache_key] = (result, time.time())
            
            return result
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            # Create cache key
            cache_key = f"{func.__name__}:{str(args)}:{str(kwargs)}"
            
            # Check cache
            if cache_key in cache:
                cached_value, cached_time = cache[cache_key]
                if time.time() - cached_time < ttl:
                    logger.debug(f"Cache hit for {func.__name__}")
                    return cached_value
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Store in cache
            cache[cache_key] = (result, time.time())
            
            return result
        
        # Return appropriate wrapper
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


async def run_with_concurrency_limit(
    tasks: list,
    max_concurrent: int = 10
) -> list:
    """
    Run tasks with concurrency limit
    
    Args:
        tasks: List of coroutines to run
        max_concurrent: Maximum concurrent tasks
    
    Returns:
        List of results
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def bounded_task(task):
        async with semaphore:
            return await task
    
    return await asyncio.gather(*[bounded_task(task) for task in tasks])


class RateLimiter:
    """
    Rate limiter for API calls
    """
    
    def __init__(self, max_calls: int, time_window: int):
        """
        Args:
            max_calls: Maximum calls allowed
            time_window: Time window in seconds
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []
    
    async def acquire(self):
        """Acquire permission to make a call"""
        now = time.time()
        
        # Remove old calls
        self.calls = [call_time for call_time in self.calls if now - call_time < self.time_window]
        
        # Check if we can make a call
        if len(self.calls) >= self.max_calls:
            # Wait until we can make a call
            wait_time = self.time_window - (now - self.calls[0])
            if wait_time > 0:
                logger.debug(f"Rate limit reached, waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
                return await self.acquire()
        
        # Record this call
        self.calls.append(now)


def rate_limit(max_calls: int, time_window: int):
    """
    Rate limiting decorator
    
    Args:
        max_calls: Maximum calls allowed
        time_window: Time window in seconds
    
    Usage:
        @rate_limit(max_calls=10, time_window=60)
        async def api_call():
            ...
    """
    limiter = RateLimiter(max_calls, time_window)
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            await limiter.acquire()
            return await func(*args, **kwargs)
        
        return wrapper
    
    return decorator


class ConnectionPool:
    """
    Generic connection pool
    """
    
    def __init__(self, create_connection: Callable, max_size: int = 10):
        """
        Args:
            create_connection: Function to create new connection
            max_size: Maximum pool size
        """
        self.create_connection = create_connection
        self.max_size = max_size
        self.pool = []
        self.in_use = set()
    
    async def acquire(self):
        """Acquire a connection from pool"""
        # Try to get from pool
        if self.pool:
            conn = self.pool.pop()
            self.in_use.add(conn)
            return conn
        
        # Create new if under limit
        if len(self.in_use) < self.max_size:
            conn = await self.create_connection()
            self.in_use.add(conn)
            return conn
        
        # Wait for available connection
        while not self.pool:
            await asyncio.sleep(0.1)
        
        return await self.acquire()
    
    async def release(self, conn):
        """Release a connection back to pool"""
        if conn in self.in_use:
            self.in_use.remove(conn)
            self.pool.append(conn)


def optimize_imports():
    """
    Optimize imports by removing unused ones
    This is a placeholder - actual implementation would use tools like autoflake
    """
    logger.info("Import optimization should be done with tools like autoflake")
    logger.info("Run: autoflake --remove-all-unused-imports --in-place --recursive .")

