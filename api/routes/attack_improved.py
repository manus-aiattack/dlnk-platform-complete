"""
Improved Attack API Routes with Real Implementation
Uses unified models and provides actual functionality
"""

from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid
import asyncio

from core.unified_models import (
    Target, AttackCampaign, AttackPlan, 
    ReconnaissanceReport, VulnerabilityReport,
    ExploitationReport, PostExploitationReport
)
from core.unified_enums import (
    AttackPhase, AttackStrategy, ScanIntensity,
    TargetType, TaskStatus, AgentStatus
)
from api.services.database import Database
from api.services.attack_manager import AttackManager
from api.services.websocket_manager import WebSocketManager
from api.services.auth import AuthService

router = APIRouter(prefix="/api/v2/attack", tags=["Attack V2 - Improved"])

# Dependency injection
db: Optional[Database] = None
ws_manager: Optional[WebSocketManager] = None
attack_manager: Optional[AttackManager] = None
auth_service: Optional[AuthService] = None


def set_dependencies(database: Database, ws_mgr: WebSocketManager, atk_mgr: AttackManager, auth_svc: AuthService):
    """Set dependencies from main.py"""
    global db, ws_manager, attack_manager, auth_service
    db = database
    ws_manager = ws_mgr
    attack_manager = atk_mgr
    auth_service = auth_svc


# ============================================================================
# Request/Response Models
# ============================================================================

class CreateTargetRequest(BaseModel):
    """Request to create a new target"""
    name: str = Field(..., description="Target name")
    url: HttpUrl = Field(..., description="Target URL")
    target_type: TargetType = Field(default=TargetType.WEB_APPLICATION)
    scan_intensity: ScanIntensity = Field(default=ScanIntensity.NORMAL)
    aggressive: bool = Field(default=False)
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class StartAttackRequest(BaseModel):
    """Request to start an attack campaign"""
    target_id: Optional[str] = None
    target_url: Optional[HttpUrl] = None
    campaign_name: str = Field(default="Auto Attack Campaign")
    attack_strategy: AttackStrategy = Field(default=AttackStrategy.BALANCED)
    scan_intensity: ScanIntensity = Field(default=ScanIntensity.NORMAL)
    phases: List[AttackPhase] = Field(default_factory=lambda: [
        AttackPhase.RECONNAISSANCE,
        AttackPhase.VULNERABILITY_DISCOVERY,
        AttackPhase.EXPLOITATION
    ])
    options: Dict[str, Any] = Field(default_factory=dict)


class AttackStatusResponse(BaseModel):
    """Attack status response"""
    campaign_id: str
    status: TaskStatus
    current_phase: AttackPhase
    progress: float
    started_at: Optional[datetime]
    updated_at: datetime
    reports_count: int
    shells_obtained: int


class AttackResultsResponse(BaseModel):
    """Attack results response"""
    campaign_id: str
    status: TaskStatus
    target: Target
    attack_plan: Optional[AttackPlan]
    reports: List[Dict[str, Any]]
    vulnerabilities_found: int
    exploits_successful: int
    shells_obtained: List[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]


# ============================================================================
# Target Management Endpoints
# ============================================================================

@router.post("/targets", response_model=Target, status_code=201)
async def create_target(request: CreateTargetRequest, req: Request):
    """
    Create a new attack target
    
    Creates a target definition that can be used for attack campaigns.
    """
    # Authentication
    api_key = req.headers.get("X-API-Key")
    if not auth_service or not api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    
    user = await auth_service.verify_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    # Create target
    target = Target(
        name=request.name,
        url=str(request.url),
        target_type=request.target_type,
        scan_intensity=request.scan_intensity,
        aggressive=request.aggressive,
        description=request.description,
        tags=request.tags,
        metadata={"created_by": user["id"]}
    )
    
    # Save to database
    if db:
        await db.save_target(target.model_dump())
    
    return target


@router.get("/targets", response_model=List[Target])
async def list_targets(req: Request, limit: int = 50):
    """
    List all targets
    
    Returns a list of all attack targets created by the user.
    """
    # Authentication
    api_key = req.headers.get("X-API-Key")
    if not auth_service or not api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    
    user = await auth_service.verify_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    # Get targets
    if db:
        targets_data = await db.get_user_targets(user["id"], limit)
        return [Target(**t) for t in targets_data]
    
    return []


@router.get("/targets/{target_id}", response_model=Target)
async def get_target(target_id: str, req: Request):
    """
    Get target details
    
    Returns detailed information about a specific target.
    """
    # Authentication
    api_key = req.headers.get("X-API-Key")
    if not auth_service or not api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    
    user = await auth_service.verify_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    # Get target
    if db:
        target_data = await db.get_target(target_id)
        if not target_data:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Check permission
        if user["role"] != "admin" and target_data.get("metadata", {}).get("created_by") != user["id"]:
            raise HTTPException(status_code=403, detail="Access denied")
        
        return Target(**target_data)
    
    raise HTTPException(status_code=404, detail="Target not found")


@router.delete("/targets/{target_id}", status_code=204)
async def delete_target(target_id: str, req: Request):
    """
    Delete a target
    
    Removes a target from the system.
    """
    # Authentication
    api_key = req.headers.get("X-API-Key")
    if not auth_service or not api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    
    user = await auth_service.verify_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    # Get target
    if db:
        target_data = await db.get_target(target_id)
        if not target_data:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Check permission
        if user["role"] != "admin" and target_data.get("metadata", {}).get("created_by") != user["id"]:
            raise HTTPException(status_code=403, detail="Access denied")
        
        await db.delete_target(target_id)
    
    return None


# ============================================================================
# Attack Campaign Endpoints
# ============================================================================

@router.post("/campaigns/start", response_model=AttackCampaign, status_code=201)
async def start_attack_campaign(
    request: StartAttackRequest,
    req: Request,
    background_tasks: BackgroundTasks
):
    """
    Start a new attack campaign
    
    Initiates an automated attack campaign against a target.
    Executes reconnaissance, vulnerability discovery, and exploitation phases.
    """
    # Authentication
    api_key = req.headers.get("X-API-Key")
    if not auth_service or not api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    
    user = await auth_service.verify_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    # Check quota
    if not await auth_service.check_quota(user["id"]):
        raise HTTPException(status_code=403, detail="Quota exceeded")
    
    # Get or create target
    target = None
    if request.target_id:
        if db:
            target_data = await db.get_target(request.target_id)
            if target_data:
                target = Target(**target_data)
    
    if not target and request.target_url:
        target = Target(
            name=f"Target-{str(request.target_url)[:50]}",
            url=str(request.target_url),
            scan_intensity=request.scan_intensity,
            metadata={"created_by": user["id"]}
        )
        if db:
            await db.save_target(target.model_dump())
    
    if not target:
        raise HTTPException(status_code=400, detail="Target ID or URL required")
    
    # Create attack campaign
    campaign = AttackCampaign(
        name=request.campaign_name,
        description=f"Automated attack campaign against {target.url}",
        targets=[target],
        current_phase=request.phases[0] if request.phases else AttackPhase.RECONNAISSANCE,
        status=TaskStatus.RUNNING,
        started_at=datetime.utcnow()
    )
    
    # Save campaign
    if db:
        await db.save_campaign(campaign.model_dump())
    
    # Start attack in background
    if attack_manager:
        background_tasks.add_task(
            attack_manager.execute_campaign,
            campaign_id=campaign.campaign_id,
            user_id=user["id"],
            phases=request.phases,
            strategy=request.attack_strategy,
            options=request.options
        )
    
    # Consume quota
    await auth_service.consume_quota(user["id"])
    
    # Send WebSocket notification
    if ws_manager:
        await ws_manager.broadcast_system({
            "type": "campaign_started",
            "campaign_id": campaign.campaign_id,
            "target": target.url
        })
    
    return campaign


@router.get("/campaigns/{campaign_id}/status", response_model=AttackStatusResponse)
async def get_campaign_status(campaign_id: str, req: Request):
    """
    Get attack campaign status
    
    Returns the current status and progress of an attack campaign.
    """
    # Authentication
    api_key = req.headers.get("X-API-Key")
    if not auth_service or not api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    
    user = await auth_service.verify_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    # Get campaign
    if not db:
        raise HTTPException(status_code=503, detail="Database not available")
    
    campaign_data = await db.get_campaign(campaign_id)
    if not campaign_data:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    campaign = AttackCampaign(**campaign_data)
    
    # Check permission
    if user["role"] != "admin":
        # Check if user owns any of the targets
        user_owns_target = any(
            t.metadata.get("created_by") == user["id"]
            for t in campaign.targets
        )
        if not user_owns_target:
            raise HTTPException(status_code=403, detail="Access denied")
    
    return AttackStatusResponse(
        campaign_id=campaign.campaign_id,
        status=campaign.status,
        current_phase=campaign.current_phase,
        progress=campaign.progress,
        started_at=campaign.started_at,
        updated_at=campaign.created_at,
        reports_count=len(campaign.reports),
        shells_obtained=len(campaign.shells_obtained)
    )


@router.get("/campaigns/{campaign_id}/results", response_model=AttackResultsResponse)
async def get_campaign_results(campaign_id: str, req: Request):
    """
    Get attack campaign results
    
    Returns detailed results including all reports, vulnerabilities, and exploits.
    """
    # Authentication
    api_key = req.headers.get("X-API-Key")
    if not auth_service or not api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    
    user = await auth_service.verify_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    # Get campaign
    if not db:
        raise HTTPException(status_code=503, detail="Database not available")
    
    campaign_data = await db.get_campaign(campaign_id)
    if not campaign_data:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    campaign = AttackCampaign(**campaign_data)
    
    # Check permission
    if user["role"] != "admin":
        user_owns_target = any(
            t.metadata.get("created_by") == user["id"]
            for t in campaign.targets
        )
        if not user_owns_target:
            raise HTTPException(status_code=403, detail="Access denied")
    
    # Count vulnerabilities and successful exploits
    vulnerabilities_count = 0
    exploits_successful = 0
    
    for report in campaign.reports:
        if isinstance(report, VulnerabilityReport):
            vulnerabilities_count += len(report.vulnerabilities)
        elif isinstance(report, ExploitationReport):
            exploits_successful += len(report.successful_attempts)
    
    return AttackResultsResponse(
        campaign_id=campaign.campaign_id,
        status=campaign.status,
        target=campaign.targets[0] if campaign.targets else None,
        attack_plan=campaign.attack_plan,
        reports=[r.model_dump() if hasattr(r, 'model_dump') else r for r in campaign.reports],
        vulnerabilities_found=vulnerabilities_count,
        exploits_successful=exploits_successful,
        shells_obtained=campaign.shells_obtained,
        started_at=campaign.started_at,
        completed_at=campaign.completed_at
    )


@router.post("/campaigns/{campaign_id}/stop", status_code=200)
async def stop_campaign(campaign_id: str, req: Request):
    """
    Stop an attack campaign
    
    Gracefully stops a running attack campaign.
    """
    # Authentication
    api_key = req.headers.get("X-API-Key")
    if not auth_service or not api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    
    user = await auth_service.verify_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    # Get campaign
    if not db:
        raise HTTPException(status_code=503, detail="Database not available")
    
    campaign_data = await db.get_campaign(campaign_id)
    if not campaign_data:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    campaign = AttackCampaign(**campaign_data)
    
    # Check permission
    if user["role"] != "admin":
        user_owns_target = any(
            t.metadata.get("created_by") == user["id"]
            for t in campaign.targets
        )
        if not user_owns_target:
            raise HTTPException(status_code=403, detail="Access denied")
    
    # Stop campaign
    if attack_manager:
        await attack_manager.stop_campaign(campaign_id)
    
    # Update status
    campaign.status = TaskStatus.CANCELLED
    campaign.completed_at = datetime.utcnow()
    
    if db:
        await db.update_campaign(campaign_id, campaign.model_dump())
    
    # Send WebSocket notification
    if ws_manager:
        await ws_manager.broadcast_system({
            "type": "campaign_stopped",
            "campaign_id": campaign_id
        })
    
    return {
        "success": True,
        "message": "Campaign stopped successfully",
        "campaign_id": campaign_id
    }


@router.get("/campaigns", response_model=List[AttackCampaign])
async def list_campaigns(req: Request, limit: int = 50, status: Optional[TaskStatus] = None):
    """
    List attack campaigns
    
    Returns a list of all attack campaigns for the user.
    """
    # Authentication
    api_key = req.headers.get("X-API-Key")
    if not auth_service or not api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    
    user = await auth_service.verify_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    # Get campaigns
    if not db:
        return []
    
    if user["role"] == "admin":
        campaigns_data = await db.get_all_campaigns(limit, status)
    else:
        campaigns_data = await db.get_user_campaigns(user["id"], limit, status)
    
    return [AttackCampaign(**c) for c in campaigns_data]


@router.delete("/campaigns/{campaign_id}", status_code=204)
async def delete_campaign(campaign_id: str, req: Request):
    """
    Delete an attack campaign
    
    Removes a campaign and all its associated data.
    """
    # Authentication
    api_key = req.headers.get("X-API-Key")
    if not auth_service or not api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    
    user = await auth_service.verify_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    # Get campaign
    if not db:
        raise HTTPException(status_code=503, detail="Database not available")
    
    campaign_data = await db.get_campaign(campaign_id)
    if not campaign_data:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    campaign = AttackCampaign(**campaign_data)
    
    # Check permission
    if user["role"] != "admin":
        user_owns_target = any(
            t.metadata.get("created_by") == user["id"]
            for t in campaign.targets
        )
        if not user_owns_target:
            raise HTTPException(status_code=403, detail="Access denied")
    
    # Delete campaign
    await db.delete_campaign(campaign_id)
    
    return None

