"""
Workflow API Routes
Handle workflow execution and management
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
from api.services.database import Database
from api.services.auth import AuthService
from api.services.websocket_manager import ws_manager
import uuid
import asyncio

router = APIRouter()

# Dependency injection - will be set by main.py
db: Database = None
auth_service: AuthService = None

def set_dependencies(database: Database, auth_svc: AuthService):
    """Set dependencies from main.py"""
    global db, auth_service
    db = database
    auth_service = auth_svc


class WorkflowExecuteRequest(BaseModel):
    workflow_path: str
    target: Dict[str, Any]


class AgentExecuteRequest(BaseModel):
    agent_name: str
    directive: str
    context: Optional[Dict[str, Any]] = {}


@router.post("/workflows/execute")
async def execute_workflow(request: WorkflowExecuteRequest):
    """Execute workflow"""
    try:
        # Generate unique workflow ID
        workflow_id = str(uuid.uuid4())

        # Create attack record
        attack_id = str(uuid.uuid4())
        await db.create_attack(attack_id, 1, request.target.get('url', ''), 'workflow')

        # Add initial log
        await db.add_agent_log(attack_id, 'workflow_engine', f"Executing workflow: {request.workflow_path}", 'running')

        # Broadcast to WebSocket
        await ws_manager.broadcast_to_logs({
            "type": "workflow_started",
            "workflow_id": workflow_id,
            "attack_id": attack_id,
            "target": request.target,
            "message": f"Workflow {request.workflow_path} started",
            "level": "info"
        })

        # Simulate workflow execution (in real implementation, this would trigger actual agents)
        asyncio.create_task(_simulate_workflow_execution(attack_id, request))

        return {
            "success": True,
            "message": f"Workflow {request.workflow_path} started successfully",
            "workflow_id": workflow_id,
            "attack_id": attack_id
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to execute workflow: {str(e)}")


@router.post("/agents/execute")
async def execute_agent(request: AgentExecuteRequest):
    """Execute single agent"""
    try:
        # Generate unique agent execution ID
        execution_id = str(uuid.uuid4())

        # Create attack record
        attack_id = str(uuid.uuid4())
        await db.create_attack(attack_id, 1, 'agent_execution', 'agent')

        # Add initial log
        await db.add_agent_log(attack_id, request.agent_name, request.directive, 'running')

        # Broadcast to WebSocket
        await ws_manager.broadcast_to_logs({
            "type": "agent_executed",
            "execution_id": execution_id,
            "attack_id": attack_id,
            "agent_name": request.agent_name,
            "directive": request.directive,
            "message": f"Agent {request.agent_name} started execution",
            "level": "info"
        })

        # Simulate agent execution
        asyncio.create_task(_simulate_agent_execution(attack_id, request))

        return {
            "success": True,
            "message": f"Agent {request.agent_name} execution started",
            "execution_id": execution_id,
            "attack_id": attack_id,
            "summary": f"Agent {request.agent_name} is processing directive: {request.directive}"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to execute agent: {str(e)}")


@router.get("/agents")
async def list_agents():
    """List available agents"""
    try:
        # In real implementation, this would scan the agents directory
        # For now, return a predefined list
        agents = [
            {
                "name": "NmapScanAgent",
                "type": "reconnaissance",
                "description": "Network scanning and port discovery",
                "capabilities": ["port_scanning", "service_detection", "os_fingerprinting"]
            },
            {
                "name": "SQLMapAgent",
                "type": "vulnerability_scanning",
                "description": "SQL injection testing and exploitation",
                "capabilities": ["sql_injection", "database_fingerprinting", "data_extraction"]
            },
            {
                "name": "XSSHunter",
                "type": "vulnerability_scanning",
                "description": "Cross-site scripting detection and analysis",
                "capabilities": ["xss_detection", "payload_generation", "exploit_verification"]
            },
            {
                "name": "CommandInjectionExploiter",
                "type": "exploitation",
                "description": "Command injection testing and shell acquisition",
                "capabilities": ["command_injection", "reverse_shell", "privilege_escalation"]
            },
            {
                "name": "SSRFAgent",
                "type": "vulnerability_scanning",
                "description": "Server-side request forgery detection",
                "capabilities": ["ssrf_detection", "internal_network_mapping", "file_access"]
            }
        ]

        return {
            "success": True,
            "agents": agents,
            "count": len(agents)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list agents: {str(e)}")


async def _simulate_workflow_execution(attack_id: str, request: WorkflowExecuteRequest):
    """Simulate workflow execution"""
    try:
        # Simulate different workflow phases
        phases = [
            ("reconnaissance", "Gathering target information"),
            ("vulnerability_scan", "Scanning for vulnerabilities"),
            ("exploitation", "Attempting exploitation"),
            ("post_exploitation", "Post-exploitation activities"),
            ("data_exfiltration", "Data collection and exfiltration")
        ]

        for phase, description in phases:
            # Update attack status
            await db.update_attack_status(attack_id, phase)

            # Add log entry
            await db.add_agent_log(attack_id, 'workflow_engine', description, 'running')

            # Broadcast progress
            await ws_manager.broadcast_to_logs({
                "type": "workflow_progress",
                "attack_id": attack_id,
                "phase": phase,
                "description": description,
                "message": f"Workflow phase: {description}",
                "level": "info"
            })

            # Simulate processing time
            await asyncio.sleep(2)

        # Complete workflow
        await db.update_attack_status(attack_id, 'success', {
            "vulnerabilities_found": 3,
            "exploits_successful": 1,
            "data_exfiltrated_bytes": 1024
        })

        # Final broadcast
        await ws_manager.broadcast_to_logs({
            "type": "workflow_completed",
            "attack_id": attack_id,
            "message": "Workflow completed successfully",
            "results": {
                "vulnerabilities_found": 3,
                "exploits_successful": 1,
                "data_exfiltrated_bytes": 1024
            },
            "level": "success"
        })

    except Exception as e:
        # Handle errors
        await db.update_attack_status(attack_id, 'failed', None, str(e))
        await ws_manager.broadcast_to_logs({
            "type": "workflow_failed",
            "attack_id": attack_id,
            "message": f"Workflow failed: {str(e)}",
            "level": "error"
        })


async def _simulate_agent_execution(attack_id: str, request: AgentExecuteRequest):
    """Simulate agent execution"""
    try:
        # Update attack status
        await db.update_attack_status(attack_id, 'running')

        # Simulate agent work
        steps = [
            "Analyzing directive",
            "Gathering information",
            "Executing task",
            "Generating results"
        ]

        for i, step in enumerate(steps):
            # Add log entry
            await db.add_agent_log(attack_id, request.agent_name, f"{step} ({i+1}/{len(steps)})", 'running')

            # Broadcast progress
            await ws_manager.broadcast_to_logs({
                "type": "agent_progress",
                "attack_id": attack_id,
                "agent_name": request.agent_name,
                "step": step,
                "progress": f"{i+1}/{len(steps)}",
                "message": f"Agent {request.agent_name}: {step}",
                "level": "info"
            })

            # Simulate processing time
            await asyncio.sleep(1)

        # Complete agent execution
        await db.update_attack_status(attack_id, 'success', {
            "agent_name": request.agent_name,
            "directive": request.directive,
            "results": "Execution completed successfully"
        })

        # Final broadcast
        await ws_manager.broadcast_to_logs({
            "type": "agent_completed",
            "attack_id": attack_id,
            "agent_name": request.agent_name,
            "message": f"Agent {request.agent_name} completed execution",
            "level": "success"
        })

    except Exception as e:
        # Handle errors
        await db.update_attack_status(attack_id, 'failed', None, str(e))
        await ws_manager.broadcast_to_logs({
            "type": "agent_failed",
            "attack_id": attack_id,
            "agent_name": request.agent_name,
            "message": f"Agent {request.agent_name} failed: {str(e)}",
            "level": "error"
        })