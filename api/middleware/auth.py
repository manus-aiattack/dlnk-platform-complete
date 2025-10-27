"""
dLNk Attack Platform - Authentication Middleware
Key-based authentication for API requests
"""

from fastapi import Request, HTTPException, status
from fastapi.security import APIKeyHeader
from typing import Optional, Dict, Any
from loguru import logger
import time

from api.database.db_service import db


# API Key Header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class AuthMiddleware:
    """Authentication middleware for dLNk Attack Platform"""
    
    @staticmethod
    async def validate_api_key(request: Request) -> Dict[str, Any]:
        """
        Validate API key from request header
        Returns key data if valid, raises HTTPException if invalid
        """
        start_time = time.time()
        
        # Get API key from header
        api_key = request.headers.get("X-API-Key")
        
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API Key required. Please provide X-API-Key header."
            )
        
        # Validate key
        is_valid, error_message = await db.validate_api_key(api_key)
        
        if not is_valid:
            logger.warning(f"❌ Invalid API key attempt: {api_key[:20]}... - {error_message}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=error_message
            )
        
        # Get key data
        key_data = await db.get_api_key(api_key)
        
        if not key_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API Key not found"
            )
        
        # Log usage
        response_time_ms = int((time.time() - start_time) * 1000)
        
        await db.log_key_usage(
            key_id=key_data['id'],
            endpoint=request.url.path,
            method=request.method,
            ip_address=request.client.host,
            user_agent=request.headers.get("User-Agent", ""),
            response_status=200,
            response_time_ms=response_time_ms
        )
        
        logger.info(f"✅ API key validated: {key_data['key_type']} - {key_data.get('user_name', 'Unknown')}")
        
        return key_data
    
    @staticmethod
    async def require_admin(request: Request) -> Dict[str, Any]:
        """
        Require admin API key
        Returns key data if admin, raises HTTPException if not
        """
        key_data = await AuthMiddleware.validate_api_key(request)
        
        if key_data['key_type'] != 'admin':
            logger.warning(f"❌ Admin access denied for key: {key_data['key_value'][:20]}...")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        return key_data
    
    @staticmethod
    async def get_current_key(request: Request) -> Optional[Dict[str, Any]]:
        """
        Get current API key data (optional)
        Returns None if no key provided
        """
        api_key = request.headers.get("X-API-Key")
        
        if not api_key:
            return None
        
        try:
            return await AuthMiddleware.validate_api_key(request)
        except HTTPException:
            return None


# Dependency functions for FastAPI
async def require_api_key(request: Request) -> Dict[str, Any]:
    """Dependency: Require valid API key"""
    return await AuthMiddleware.validate_api_key(request)


async def require_admin_key(request: Request) -> Dict[str, Any]:
    """Dependency: Require admin API key"""
    return await AuthMiddleware.require_admin(request)


async def optional_api_key(request: Request) -> Optional[Dict[str, Any]]:
    """Dependency: Optional API key"""
    return await AuthMiddleware.get_current_key(request)

