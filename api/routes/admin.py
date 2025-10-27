"""
dLNk Attack Platform - Admin API Routes
Admin-only endpoints for key management, user management, and system settings
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

from api.middleware.auth import require_admin_key
from api.database.db_service import db
from loguru import logger


router = APIRouter(prefix="/api/admin", tags=["Admin"])


# Dependency injection - will be set by main.py
db_instance = None
auth_service_instance = None

def set_dependencies(database, auth_svc):
    """Set dependencies from main.py"""
    global db_instance, auth_service_instance
    db_instance = database
    auth_service_instance = auth_svc


# ===== Request Models =====

class CreateKeyRequest(BaseModel):
    key_type: str = Field(..., description="Key type: 'admin' or 'user'")
    user_name: Optional[str] = Field(None, description="User name")
    expires_in_days: Optional[int] = Field(None, description="Expiration in days")
    usage_limit: Optional[int] = Field(None, description="Usage limit (NULL = unlimited)")
    notes: Optional[str] = Field(None, description="Notes")


class UpdateKeyRequest(BaseModel):
    user_name: Optional[str] = None
    is_active: Optional[bool] = None
    usage_limit: Optional[int] = None
    notes: Optional[str] = None


class UpdateSettingRequest(BaseModel):
    value: str = Field(..., description="Setting value")


# ===== Key Management Endpoints =====

@router.post("/keys/create")
async def create_api_key(
    request: CreateKeyRequest,
    admin_key: dict = Depends(require_admin_key)
):
    """
    Create new API key (Admin only)
    
    **Key Types:**
    - `admin`: Unlimited usage, no expiration
    - `user`: Limited usage, can expire
    
    **Example:**
    ```json
    {
        "key_type": "user",
        "user_name": "John Doe",
        "expires_in_days": 30,
        "usage_limit": 100,
        "notes": "Test user"
    }
    ```
    """
    try:
        # Validate key_type
        if request.key_type not in ['admin', 'user']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="key_type must be 'admin' or 'user'"
            )
        
        # Admin keys should not have limits
        if request.key_type == 'admin':
            request.expires_in_days = None
            request.usage_limit = None
        
        # Create key
        key = await db.create_api_key(
            key_type=request.key_type,
            user_name=request.user_name,
            expires_in_days=request.expires_in_days,
            usage_limit=request.usage_limit,
            notes=request.notes
        )
        
        logger.info(f"✅ Admin {admin_key.get('user_name')} created key: {key['key_value']}")
        
        return {
            "success": True,
            "message": "API key created successfully",
            "key": key
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to create API key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/keys")
async def list_api_keys(
    key_type: Optional[str] = None,
    is_active: Optional[bool] = None,
    admin_key: dict = Depends(require_admin_key)
):
    """
    List all API keys (Admin only)
    
    **Filters:**
    - `key_type`: Filter by key type ('admin' or 'user')
    - `is_active`: Filter by active status
    """
    try:
        keys = await db.list_api_keys(key_type=key_type, is_active=is_active)
        
        return {
            "success": True,
            "count": len(keys),
            "keys": keys
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to list API keys: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/keys/{key_id}")
async def get_api_key(
    key_id: str,
    admin_key: dict = Depends(require_admin_key)
):
    """Get API key details (Admin only)"""
    try:
        key = await db.get_api_key(key_id)
        
        if not key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        return {
            "success": True,
            "key": key
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get API key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.patch("/keys/{key_id}")
async def update_api_key(
    key_id: str,
    request: UpdateKeyRequest,
    admin_key: dict = Depends(require_admin_key)
):
    """Update API key (Admin only)"""
    try:
        # Build update dict
        updates = {}
        if request.user_name is not None:
            updates['user_name'] = request.user_name
        if request.is_active is not None:
            updates['is_active'] = request.is_active
        if request.usage_limit is not None:
            updates['usage_limit'] = request.usage_limit
        if request.notes is not None:
            updates['notes'] = request.notes
        
        if not updates:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields to update"
            )
        
        # Update key
        key = await db.update_api_key(key_id, **updates)
        
        if not key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        logger.info(f"✅ Admin {admin_key.get('user_name')} updated key: {key_id}")
        
        return {
            "success": True,
            "message": "API key updated successfully",
            "key": key
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to update API key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/keys/{key_id}/revoke")
async def revoke_api_key(
    key_id: str,
    admin_key: dict = Depends(require_admin_key)
):
    """Revoke API key (Admin only)"""
    try:
        success = await db.revoke_api_key(key_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        logger.info(f"✅ Admin {admin_key.get('user_name')} revoked key: {key_id}")
        
        return {
            "success": True,
            "message": "API key revoked successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to revoke API key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete("/keys/{key_id}")
async def delete_api_key(
    key_id: str,
    admin_key: dict = Depends(require_admin_key)
):
    """Delete API key (Admin only)"""
    try:
        success = await db.delete_api_key(key_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        logger.info(f"✅ Admin {admin_key.get('user_name')} deleted key: {key_id}")
        
        return {
            "success": True,
            "message": "API key deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to delete API key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# ===== Statistics Endpoints =====

@router.get("/stats")
async def get_statistics(
    admin_key: dict = Depends(require_admin_key)
):
    """Get system statistics (Admin only)"""
    try:
        attack_stats = await db.get_attack_statistics()
        key_stats = await db.get_key_statistics()
        
        return {
            "success": True,
            "attack_statistics": attack_stats,
            "key_statistics": key_stats
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to get statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/stats/attacks")
async def get_attack_statistics(
    admin_key: dict = Depends(require_admin_key)
):
    """Get attack statistics (Admin only)"""
    try:
        stats = await db.get_attack_statistics()
        
        return {
            "success": True,
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to get attack statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/stats/keys")
async def get_key_statistics(
    admin_key: dict = Depends(require_admin_key)
):
    """Get key statistics (Admin only)"""
    try:
        stats = await db.get_key_statistics()
        
        return {
            "success": True,
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to get key statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# ===== System Settings Endpoints =====

@router.get("/settings")
async def get_settings(
    admin_key: dict = Depends(require_admin_key)
):
    """Get all system settings (Admin only)"""
    try:
        settings = {
            "line_contact_url": await db.get_setting("line_contact_url"),
            "default_usage_limit": await db.get_setting("default_usage_limit"),
            "rate_limit_per_minute": await db.get_setting("rate_limit_per_minute"),
            "attack_timeout_seconds": await db.get_setting("attack_timeout_seconds"),
            "data_retention_days": await db.get_setting("data_retention_days")
        }
        
        return {
            "success": True,
            "settings": settings
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to get settings: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/settings/{key}")
async def get_setting(
    key: str,
    admin_key: dict = Depends(require_admin_key)
):
    """Get system setting (Admin only)"""
    try:
        value = await db.get_setting(key)
        
        if value is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Setting not found"
            )
        
        return {
            "success": True,
            "key": key,
            "value": value
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get setting: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.put("/settings/{key}")
async def update_setting(
    key: str,
    request: UpdateSettingRequest,
    admin_key: dict = Depends(require_admin_key)
):
    """
    Update system setting (Admin only)
    
    **Available Settings:**
    - `line_contact_url`: LINE contact URL for admin
    - `default_usage_limit`: Default usage limit for new keys
    - `rate_limit_per_minute`: API rate limit per minute
    - `attack_timeout_seconds`: Default attack timeout
    - `data_retention_days`: Days to retain attack data
    """
    try:
        await db.set_setting(key, request.value)
        
        logger.info(f"✅ Admin {admin_key.get('user_name')} updated setting: {key} = {request.value}")
        
        return {
            "success": True,
            "message": "Setting updated successfully",
            "key": key,
            "value": request.value
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to update setting: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# ===== User Management Endpoints =====

@router.get("/users")
async def list_users(
    admin_key: dict = Depends(require_admin_key)
):
    """List all users (Admin only)"""
    try:
        # Get user keys
        keys = await db.list_api_keys(key_type='user')
        
        # Get statistics for each user
        users = []
        for key in keys:
            attacks = await db.list_attacks(key_id=key['id'])
            
            users.append({
                "key_id": key['id'],
                "key_value": key['key_value'],
                "user_name": key['user_name'],
                "created_at": key['created_at'],
                "is_active": key['is_active'],
                "usage_count": key['usage_count'],
                "usage_limit": key['usage_limit'],
                "total_attacks": len(attacks),
                "last_used_at": key['last_used_at']
            })
        
        return {
            "success": True,
            "count": len(users),
            "users": users
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to list users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/users/{key_id}/attacks")
async def get_user_attacks(
    key_id: str,
    admin_key: dict = Depends(require_admin_key)
):
    """Get user's attack history (Admin only)"""
    try:
        attacks = await db.list_attacks(key_id=key_id)
        
        return {
            "success": True,
            "count": len(attacks),
            "attacks": attacks
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to get user attacks: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

