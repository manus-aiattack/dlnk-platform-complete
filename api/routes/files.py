"""
Files API Routes
"""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
import os
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


@router.get("/{file_id}/download")
async def download_file(file_id: int, req: Request):
    """ดาวน์โหลดไฟล์"""
    # Get user
    api_key = req.headers.get("X-API-Key")
    user = await auth_service.verify_key(api_key)
    
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Get file info
    file_info = await db.get_file_by_id(file_id)
    
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Check permission
    if user["role"] != "admin" and file_info["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Check if file exists
    file_path = file_info["file_path"]
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found on disk")
    
    # Return file
    return FileResponse(
        path=file_path,
        filename=file_info["file_name"],
        media_type="application/octet-stream"
    )


@router.get("/attack/{attack_id}")
async def get_attack_files(attack_id: str, req: Request):
    """ดูรายการไฟล์ของการโจมตี"""
    # Get user
    api_key = req.headers.get("X-API-Key")
    user = await auth_service.verify_key(api_key)
    
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Get attack
    attack = await db.get_attack(attack_id)
    
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")
    
    # Check permission
    if user["role"] != "admin" and attack["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get files
    files = await db.get_attack_files(attack_id)
    
    return {"files": files}

