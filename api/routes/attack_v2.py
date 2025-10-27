"""
dLNk Attack Platform - Attack API Routes
API endpoints for launching and managing attacks
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid

from api.middleware.auth import require_api_key
from api.database.db_service import db
from core.attack_orchestrator import orchestrator

router = APIRouter(prefix="/api/attack", tags=["Attack"])


# Request Models
class AttackRequest(BaseModel):
    target_url: HttpUrl
    attack_mode: Optional[str] = 'auto'  # auto, stealth, aggressive
    
    class Config:
        json_schema_extra = {
            "example": {
                "target_url": "http://localhost:8000",
                "attack_mode": "auto"
            }
        }


class AttackResponse(BaseModel):
    attack_id: str
    target_url: str
    status: str
    message: str


class AttackStatusResponse(BaseModel):
    attack_id: str
    target_url: str
    status: str
    progress: int
    started_at: datetime
    completed_at: Optional[datetime]
    vulnerabilities_found: int
    exploits_successful: int
    data_exfiltrated_bytes: int


class VulnerabilityResponse(BaseModel):
    id: str
    attack_id: str
    vuln_type: str
    severity: str
    title: str
    description: Optional[str]
    url: Optional[str]
    parameter: Optional[str]
    cvss_score: Optional[float]
    discovered_at: datetime


# Endpoints

@router.post("/launch", response_model=AttackResponse)
async def launch_attack(
    request: AttackRequest,
    background_tasks: BackgroundTasks,
    api_key: Dict[str, Any] = Depends(require_api_key)
):
    """
    🎯 Launch automated attack
    
    This endpoint starts a fully automated attack against the target URL.
    The attack runs in the background and includes:
    
    1. **Reconnaissance** - Target analysis
    2. **Scanning** - Vulnerability discovery
    3. **AI Planning** - Attack strategy
    4. **Exploitation** - Execute exploits
    5. **Post-Exploitation** - Privilege escalation
    6. **Data Exfiltration** - Extract sensitive data
    7. **Cleanup** - Remove traces
    
    **Attack Modes:**
    - `auto`: Balanced approach (recommended)
    - `stealth`: Maximum stealth, slower
    - `aggressive`: Maximum speed, less stealth
    
    **Returns:**
    - `attack_id`: Use this to track attack progress
    - `status`: Initial status (will be 'queued')
    """
    
    # Generate attack ID
    attack_id = str(uuid.uuid4())
    
    # Create attack record
    await db.create_attack(
        attack_id=attack_id,
        api_key_id=api_key['id'],
        target_url=str(request.target_url),
        attack_mode=request.attack_mode,
        status="queued"
    )
    
    # Start attack in background
    background_tasks.add_task(
        orchestrator.start_attack,
        attack_id=attack_id,
        target_url=str(request.target_url),
        attack_mode=request.attack_mode
    )
    
    return AttackResponse(
        attack_id=attack_id,
        target_url=str(request.target_url),
        status="queued",
        message="Attack launched successfully. Use /api/attack/{attack_id}/status to track progress."
    )


@router.get("/{attack_id}/status", response_model=AttackStatusResponse)
async def get_attack_status(
    attack_id: str,
    api_key: Dict[str, Any] = Depends(require_api_key)
):
    """
    📊 Get attack status
    
    Returns current status and progress of an attack.
    
    **Status Values:**
    - `queued`: Attack is queued
    - `reconnaissance`: Analyzing target
    - `scanning`: Scanning for vulnerabilities
    - `vulnerability_analysis`: AI analyzing vulnerabilities
    - `attack_planning`: AI creating attack plan
    - `exploitation`: Exploiting vulnerabilities
    - `post_exploitation`: Post-exploitation activities
    - `data_exfiltration`: Exfiltrating data
    - `cleanup`: Cleaning up
    - `completed`: Attack completed successfully
    - `failed`: Attack failed
    - `stopped`: Attack was stopped
    
    **Progress:** 0-100 percentage
    """
    
    attack = await db.get_attack(attack_id)
    
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")
    
    # Check ownership
    if attack["api_key_id"] != api_key['id'] and api_key['key_type'] != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    return AttackStatusResponse(
        attack_id=attack_id,
        target_url=attack["target_url"],
        status=attack["status"],
        progress=attack["progress"],
        started_at=attack["started_at"],
        completed_at=attack["completed_at"],
        vulnerabilities_found=attack["vulnerabilities_found"],
        exploits_successful=attack["exploits_successful"],
        data_exfiltrated_bytes=attack["data_exfiltrated_bytes"]
    )


@router.get("/{attack_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def get_attack_vulnerabilities(
    attack_id: str,
    api_key: Dict[str, Any] = Depends(require_api_key)
):
    """
    🔍 Get discovered vulnerabilities
    
    Returns all vulnerabilities discovered during the attack.
    """
    
    attack = await db.get_attack(attack_id)
    
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")
    
    # Check ownership
    if attack["api_key_id"] != api_key['id'] and api_key['key_type'] != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    vulnerabilities = await db.list_vulnerabilities(attack_id)
    
    return [
        VulnerabilityResponse(
            id=str(vuln["id"]),
            attack_id=attack_id,
            vuln_type=vuln["vuln_type"],
            severity=vuln["severity"],
            title=vuln["title"],
            description=vuln["description"],
            url=vuln["url"],
            parameter=vuln["parameter"],
            cvss_score=vuln["cvss_score"],
            discovered_at=vuln["discovered_at"]
        )
        for vuln in vulnerabilities
    ]


@router.post("/{attack_id}/stop")
async def stop_attack(
    attack_id: str,
    api_key: Dict[str, Any] = Depends(require_api_key)
):
    """
    🛑 Stop running attack
    
    Stops an attack that is currently running.
    """
    
    attack = await db.get_attack(attack_id)
    
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")
    
    # Check ownership
    if attack["api_key_id"] != api_key['id'] and api_key['key_type'] != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    if attack["status"] in ["completed", "failed", "stopped"]:
        raise HTTPException(status_code=400, detail="Attack is not running")
    
    success = await orchestrator.stop_attack(attack_id)
    
    if success:
        return {"message": "Attack stopped successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to stop attack")


@router.get("/history", response_model=List[AttackStatusResponse])
async def get_attack_history(
    limit: int = 10,
    api_key: Dict[str, Any] = Depends(require_api_key)
):
    """
    📜 Get attack history
    
    Returns list of past attacks for the current user.
    Admin keys can see all attacks.
    """
    
    if api_key['key_type'] == "admin":
        # Admin sees all attacks
        attacks = await db.list_attacks(limit=limit)
    else:
        # User sees only their attacks
        attacks = await db.list_attacks(api_key_id=api_key['id'], limit=limit)
    
    return [
        AttackStatusResponse(
            attack_id=str(attack["id"]),
            target_url=attack["target_url"],
            status=attack["status"],
            progress=attack["progress"],
            started_at=attack["started_at"],
            completed_at=attack["completed_at"],
            vulnerabilities_found=attack["vulnerabilities_found"],
            exploits_successful=attack["exploits_successful"],
            data_exfiltrated_bytes=attack["data_exfiltrated_bytes"]
        )
        for attack in attacks
    ]


@router.delete("/{attack_id}")
async def delete_attack(
    attack_id: str,
    api_key: Dict[str, Any] = Depends(require_api_key)
):
    """
    🗑️ Delete attack record
    
    Deletes an attack and all associated data.
    Only admins or attack owners can delete.
    """
    
    attack = await db.get_attack(attack_id)
    
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")
    
    # Check ownership
    if attack["api_key_id"] != api_key['id'] and api_key['key_type'] != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Delete attack
    await db.delete_attack(attack_id)
    
    return {"message": "Attack deleted successfully"}

