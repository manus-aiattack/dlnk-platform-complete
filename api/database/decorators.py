"""
Database decorators for dLNk Attack Platform
Ensures database pool is available before operations
"""

from functools import wraps
from typing import Callable, Any
from loguru import logger


def require_pool(func: Callable) -> Callable:
    """
    Decorator to ensure database pool is initialized before operation
    
    Usage:
        @require_pool
        async def some_db_operation(self):
            async with self.pool.acquire() as conn:
                ...
    """
    @wraps(func)
    async def wrapper(self, *args, **kwargs) -> Any:
        # Check if pool exists
        if not hasattr(self, 'pool'):
            error_msg = f"Database pool not found in {self.__class__.__name__}"
            logger.error(f"❌ {error_msg}")
            raise AttributeError(error_msg)
        
        # Check if pool is initialized
        if self.pool is None:
            error_msg = f"Database pool not initialized in {self.__class__.__name__}. Call connect() first."
            logger.error(f"❌ {error_msg}")
            raise RuntimeError(error_msg)
        
        # Check if pool is closed
        if hasattr(self.pool, '_closed') and self.pool._closed:
            error_msg = f"Database pool is closed in {self.__class__.__name__}"
            logger.error(f"❌ {error_msg}")
            raise RuntimeError(error_msg)
        
        try:
            # Execute the function
            return await func(self, *args, **kwargs)
        except Exception as e:
            logger.error(f"❌ Database operation failed in {func.__name__}: {e}")
            raise
    
    return wrapper


def require_pool_sync(func: Callable) -> Callable:
    """
    Decorator for synchronous functions that need database pool
    
    Usage:
        @require_pool_sync
        def some_sync_operation(self):
            ...
    """
    @wraps(func)
    def wrapper(self, *args, **kwargs) -> Any:
        # Check if pool exists
        if not hasattr(self, 'pool'):
            error_msg = f"Database pool not found in {self.__class__.__name__}"
            logger.error(f"❌ {error_msg}")
            raise AttributeError(error_msg)
        
        # Check if pool is initialized
        if self.pool is None:
            error_msg = f"Database pool not initialized in {self.__class__.__name__}. Call connect() first."
            logger.error(f"❌ {error_msg}")
            raise RuntimeError(error_msg)
        
        try:
            # Execute the function
            return func(self, *args, **kwargs)
        except Exception as e:
            logger.error(f"❌ Database operation failed in {func.__name__}: {e}")
            raise
    
    return wrapper

