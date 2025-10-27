"""
Shared API Dependencies
"""

from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import os


# Security
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """
    Get current authenticated user from token
    
    Args:
        credentials: HTTP Bearer credentials
        
    Returns:
        User dictionary
        
    Raises:
        HTTPException: If authentication fails
    """
    token = credentials.credentials
    
    # TODO: Implement actual token verification
    # For now, just check if token exists
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Mock user for now
    return {
        "id": "user-123",
        "username": "admin",
        "role": "admin"
    }


async def get_current_admin_user(
    current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Get current user and verify admin role
    
    Args:
        current_user: Current user from get_current_user
        
    Returns:
        Admin user dictionary
        
    Raises:
        HTTPException: If user is not admin
    """
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


async def verify_api_key(
    x_api_key: Optional[str] = Header(None)
) -> dict:
    """
    Verify API key from header
    
    Args:
        x_api_key: API key from X-API-Key header
        
    Returns:
        User dictionary
        
    Raises:
        HTTPException: If API key is invalid
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required"
        )
    
    # TODO: Implement actual API key verification
    # For now, just check if key exists
    if not x_api_key.startswith("DLNK-"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    # Mock user for now
    return {
        "id": "user-123",
        "username": "admin",
        "role": "admin",
        "api_key": x_api_key
    }


def get_database():
    """
    Get database session
    
    Yields:
        Database session
    """
    # TODO: Implement actual database session
    # For now, return None
    yield None


def get_services():
    """
    Get service instances
    
    Returns:
        Dictionary of service instances
    """
    # TODO: Implement actual service initialization
    return {
        "attack_service": None,
        "file_service": None,
        "report_service": None,
        "notification_service": None,
        "system_service": None
    }

