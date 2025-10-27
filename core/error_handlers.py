"""
Error Handling Decorators for dLNk Attack Platform
Provides comprehensive error handling for critical operations
"""

import asyncio
import functools
from typing import Callable, Any, Dict, Optional
from loguru import logger


def handle_errors(
    default_return: Any = None,
    log_level: str = "error",
    raise_on_error: bool = False
):
    """
    Decorator to handle errors in functions
    
    Args:
        default_return: Value to return on error (default: None)
        log_level: Log level for errors (default: "error")
        raise_on_error: Whether to re-raise the exception (default: False)
    
    Usage:
        @handle_errors(default_return={})
        async def my_function():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                error_msg = f"{func.__name__}() failed: {type(e).__name__}: {str(e)}"
                
                if log_level == "critical":
                    logger.critical(error_msg)
                elif log_level == "error":
                    logger.error(error_msg)
                elif log_level == "warning":
                    logger.warning(error_msg)
                else:
                    logger.debug(error_msg)
                
                if raise_on_error:
                    raise
                
                return default_return
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_msg = f"{func.__name__}() failed: {type(e).__name__}: {str(e)}"
                
                if log_level == "critical":
                    logger.critical(error_msg)
                elif log_level == "error":
                    logger.error(error_msg)
                elif log_level == "warning":
                    logger.warning(error_msg)
                else:
                    logger.debug(error_msg)
                
                if raise_on_error:
                    raise
                
                return default_return
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def handle_agent_errors(func: Callable) -> Callable:
    """
    Specialized error handler for agent operations
    Returns AgentData with error information on failure
    
    Usage:
        @handle_agent_errors
        async def run(self, directive, context):
            ...
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> Dict[str, Any]:
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            error_msg = f"{func.__name__}() failed: {type(e).__name__}: {str(e)}"
            logger.error(error_msg)
            
            # Return AgentData format
            return {
                "success": False,
                "error": error_msg,
                "error_type": type(e).__name__,
                "data": {},
                "message": f"Agent execution failed: {str(e)}"
            }
    
    return wrapper


def handle_exfiltration_errors(func: Callable) -> Callable:
    """
    Specialized error handler for data exfiltration operations
    Returns dict with success=False on error
    
    Usage:
        @handle_exfiltration_errors
        async def dump_databases(self, db_access):
            ...
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> Dict[str, Any]:
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            error_msg = f"{func.__name__}() failed: {type(e).__name__}: {str(e)}"
            logger.error(error_msg)
            
            return {
                "success": False,
                "error": error_msg,
                "error_type": type(e).__name__,
                "files": [],
                "databases": [],
                "total_size": 0
            }
    
    return wrapper


def handle_exploit_errors(func: Callable) -> Callable:
    """
    Specialized error handler for exploit operations
    Returns dict with success=False on error
    
    Usage:
        @handle_exploit_errors
        async def exploit_sqli(self, target, payload):
            ...
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> Dict[str, Any]:
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            error_msg = f"{func.__name__}() failed: {type(e).__name__}: {str(e)}"
            logger.error(error_msg)
            
            return {
                "success": False,
                "error": error_msg,
                "error_type": type(e).__name__,
                "exploited": False,
                "shell_obtained": False,
                "vulnerabilities": []
            }
    
    return wrapper


def safe_execute(func: Callable, *args, default=None, **kwargs) -> Any:
    """
    Safely execute a function and return default on error
    
    Usage:
        result = safe_execute(risky_function, arg1, arg2, default={})
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        logger.error(f"safe_execute() failed for {func.__name__}: {e}")
        return default


async def safe_execute_async(func: Callable, *args, default=None, **kwargs) -> Any:
    """
    Safely execute an async function and return default on error
    
    Usage:
        result = await safe_execute_async(risky_async_function, arg1, arg2, default={})
    """
    try:
        return await func(*args, **kwargs)
    except Exception as e:
        logger.error(f"safe_execute_async() failed for {func.__name__}: {e}")
        return default

