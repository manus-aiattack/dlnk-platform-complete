#!/usr/bin/env python3
"""
Advanced Vanchin Chat API with full Agent capabilities
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional
from loguru import logger

from core.advanced_vanchin_agent import advanced_agent


router = APIRouter(prefix="/api/vanchin", tags=["Vanchin Chat Advanced"])


class ChatRequest(BaseModel):
    """Chat request"""
    message: str
    use_agent: bool = True  # Use advanced agent mode


class ChatResponse(BaseModel):
    """Chat response"""
    response: str
    agent_used: bool
    timestamp: str


class SettingsRequest(BaseModel):
    """Settings update request"""
    vc_api_key: Optional[str] = None
    model: Optional[str] = None


@router.post("/chat/advanced", response_model=ChatResponse)
async def chat_advanced(request: ChatRequest):
    """
    Chat with Advanced Vanchin AI Agent
    
    This endpoint uses the full AOA (Advanced Offensive Agent) with:
    - File read/write access
    - Shell command execution
    - Git operations
    - System monitoring
    - Self-healing
    """
    try:
        logger.info(f"[Vanchin Chat Advanced] User: {request.message[:100]}...")
        
        if request.use_agent:
            # Use advanced agent
            response = await advanced_agent.chat(request.message)
        else:
            # Use simple chat
            from core.vanchin_client import vanchin_client
            response = vanchin_client.chat([
                {"role": "user", "content": request.message}
            ])
        
        from datetime import datetime
        
        return ChatResponse(
            response=response,
            agent_used=request.use_agent,
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"[Vanchin Chat Advanced] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/settings")
async def update_settings(request: SettingsRequest):
    """
    Update Vanchin AI settings
    
    Allows changing:
    - VC_API_KEY
    - Model endpoint
    """
    try:
        import os
        
        updated = []
        
        if request.vc_api_key:
            # Update environment variable
            os.environ["VC_API_KEY"] = request.vc_api_key
            
            # Update .env file
            env_path = "/home/ubuntu/aiprojectattack/.env"
            with open(env_path, 'r') as f:
                lines = f.readlines()
            
            with open(env_path, 'w') as f:
                for line in lines:
                    if line.startswith("VC_API_KEY="):
                        f.write(f"VC_API_KEY={request.vc_api_key}\n")
                    else:
                        f.write(line)
            
            updated.append("VC_API_KEY")
            logger.success("[Settings] Updated VC_API_KEY")
        
        if request.model:
            # Update model
            from core.vanchin_client import vanchin_client
            vanchin_client.model = request.model
            updated.append("model")
            logger.success(f"[Settings] Updated model: {request.model}")
        
        return {
            "success": True,
            "updated": updated,
            "message": f"Updated: {', '.join(updated)}"
        }
        
    except Exception as e:
        logger.error(f"[Settings] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/files")
async def list_project_files(path: str = "."):
    """
    List files in project directory
    """
    try:
        files = advanced_agent.list_files(path)
        return {
            "path": path,
            "files": files,
            "count": len(files)
        }
    except Exception as e:
        logger.error(f"[Files] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/file/{path:path}")
async def read_file(path: str):
    """
    Read file content
    """
    try:
        content = advanced_agent.read_file(path)
        return {
            "path": path,
            "content": content,
            "size": len(content)
        }
    except Exception as e:
        logger.error(f"[File Read] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/file/{path:path}")
async def write_file(path: str, content: str):
    """
    Write file content
    """
    try:
        result = advanced_agent.write_file(path, content)
        return {
            "success": True,
            "message": result
        }
    except Exception as e:
        logger.error(f"[File Write] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute")
async def execute_command(command: str):
    """
    Execute shell command
    """
    try:
        result = advanced_agent.execute_command(command)
        return result
    except Exception as e:
        logger.error(f"[Execute] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def system_health():
    """
    Check system health
    """
    try:
        health = advanced_agent.check_system_health()
        return health
    except Exception as e:
        logger.error(f"[Health] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

