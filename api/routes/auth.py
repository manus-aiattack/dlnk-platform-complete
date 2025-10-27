"""
Authentication API Routes
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime
from api.services.database import Database
from api.services.auth import AuthService

router = APIRouter()

# Dependency injection - will be set by main.py
db: Database = None
auth_service: AuthService = None

def set_dependencies(database: Database, auth_svc: AuthService):
    """Set dependencies from main.py"""
    global db, auth_service
    db = database
    auth_service = auth_svc


class LoginRequest(BaseModel):
    api_key: str


@router.post("/login")
async def login(request: LoginRequest):
    """Login with API Key"""
    try:
        user = await auth_service.verify_key(request.api_key)

        if not user:
            raise HTTPException(status_code=401, detail="Invalid API Key")

        if not user["is_active"]:
            raise HTTPException(status_code=403, detail="Account is disabled")

        # Update quota usage
        await db.update_quota(user["id"], 1)

        return {
            "success": True,
            "message": "Login successful",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "quota_limit": user["quota_limit"],
                "quota_used": user["quota_used"] + 1 if user["quota_used"] is not None else 1,
                "remaining_quota": (user["quota_limit"] - user["quota_used"] - 1) if user["quota_limit"] is not None else "unlimited",
                "api_key": user["api_key"],
                "last_login": user["last_login"]
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")


@router.post("/verify")
async def verify(request: LoginRequest):
    """Verify API Key"""
    try:
        user = await auth_service.verify_key(request.api_key)

        if not user:
            raise HTTPException(status_code=401, detail="Invalid API Key")

        if not user["is_active"]:
            raise HTTPException(status_code=403, detail="Account is disabled")

        return {
            "valid": True,
            "message": "API Key is valid",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "quota_limit": user["quota_limit"],
                "quota_used": user["quota_used"],
                "remaining_quota": user["quota_limit"] - user["quota_used"] if user["quota_limit"] is not None else "unlimited"
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@router.post("/generate-admin-key")
async def generate_admin_key():
    """Generate default admin key (for setup only)"""
    try:
        # Check if admin key already exists
        existing_admin = await db.get_user_by_key("admin")
        if existing_admin:
            raise HTTPException(status_code=400, detail="Admin key already exists")

        # Generate admin key
        admin_data = await auth_service.create_user_key(
            username="admin",
            role="admin",
            quota_limit=None  # Unlimited for admin
        )

        # Save to file
        with open('/mnt/c/projecattack/Manus/ADMIN_KEY.txt', 'w') as f:
            f.write(f"Admin API Key: {admin_data['api_key']}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Role: admin\n")
            f.write(f"Username: admin\n")

        return {
            "success": True,
            "message": "Admin key generated successfully",
            "admin_key": admin_data['api_key'],
            "note": "Admin key saved to ADMIN_KEY.txt"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate admin key: {str(e)}")


@router.post("/logout")
async def logout():
    """Logout (placeholder - in real implementation, this would invalidate tokens)"""
    return {"success": True, "message": "Logged out successfully"}

