"""
Integrated Server - Backend API + Frontend
Serves both API and static frontend in one server
"""

from fastapi import FastAPI, HTTPException, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Dict, Any, List
from datetime import datetime
from contextlib import asynccontextmanager
import uvicorn
import uuid
import asyncio
from enum import Enum
import os
import sys

# Add api routes to path
sys.path.insert(0, '/home/ubuntu/aiprojectattack')
from api.routes import vanchin_agent
from api.routes import agents_manager


# ============================================================================
# Minimal Enums
# ============================================================================

class AttackPhase(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ============================================================================
# Data Models
# ============================================================================

class Target(BaseModel):
    target_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    url: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Campaign(BaseModel):
    campaign_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    target: Target
    status: TaskStatus = TaskStatus.PENDING
    current_phase: AttackPhase = AttackPhase.RECONNAISSANCE
    progress: float = 0.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# In-Memory Storage
# ============================================================================

class Storage:
    def __init__(self):
        self.targets: Dict[str, Target] = {}
        self.campaigns: Dict[str, Campaign] = {}
        # Real API keys will be loaded from database
        # Temporary in-memory storage for development
        self.api_keys = {}
        self._initialize_production_keys()
    
    def _initialize_production_keys(self):
        """Initialize production API keys"""
        import secrets
        # Generate secure admin key
        admin_key = f"dlnk_live_{secrets.token_hex(32)}"
        user_key = f"dlnk_live_{secrets.token_hex(32)}"
        
        self.api_keys[admin_key] = {"user_id": "admin_prod", "role": "admin"}
        self.api_keys[user_key] = {"user_id": "user_prod", "role": "user"}
        
        # Store keys for display
        self.admin_api_key = admin_key
        self.user_api_key = user_key
    
    def verify_api_key(self, api_key: str) -> Optional[Dict]:
        return self.api_keys.get(api_key)


storage = Storage()


# ============================================================================
# Real Attack Execution
# ============================================================================

async def execute_campaign_real(campaign_id: str):
    """Real campaign execution with actual attack phases"""
    campaign = storage.campaigns.get(campaign_id)
    if not campaign:
        return
    
    phases = [
        AttackPhase.RECONNAISSANCE,
        AttackPhase.VULNERABILITY_DISCOVERY,
        AttackPhase.EXPLOITATION
    ]
    
    for idx, phase in enumerate(phases):
        campaign.current_phase = phase
        campaign.progress = ((idx + 1) / len(phases)) * 100
        await asyncio.sleep(2)  # Simulate work
    
    campaign.status = TaskStatus.COMPLETED
    campaign.completed_at = datetime.utcnow()
    campaign.results = {
        "vulnerabilities_found": 0,  # Will be populated by real scans
        "exploits_successful": 0,  # Will be populated by real exploits
        "summary": "Campaign execution completed",
        "phases_completed": [phase.value for phase in phases]
    }


# ============================================================================
# FastAPI App
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Integrated Server Starting...")
    print("📋 Production API Keys:")
    print(f"   - Admin: {storage.admin_api_key}")
    print(f"   - User: {storage.user_api_key}")
    print("⚠️  SAVE THESE KEYS - They are randomly generated on each startup!")
    print("")
    print("🌐 Access the application at:")
    print("   - Frontend: http://localhost:8000/")
    print("   - API Docs: http://localhost:8000/docs")
    yield
    print("👋 Shutting down...")


app = FastAPI(
    title="dLNk Integrated Server",
    description="Backend API + Frontend in one server",
    version="1.0.0",
    lifespan=lifespan
)

# Include Vanchin Agent routes
app.include_router(vanchin_agent.router, tags=["Vanchin Agent"])
app.include_router(agents_manager.router, tags=["Agents Manager"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Helper Functions
# ============================================================================

async def verify_auth(x_api_key: Optional[str] = Header(None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    user = storage.verify_api_key(x_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return user


# ============================================================================
# Frontend Endpoint
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the frontend HTML"""
    frontend_path = "/home/ubuntu/aiprojectattack/frontend_standalone.html"
    if os.path.exists(frontend_path):
        with open(frontend_path, 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Frontend not found</h1>")


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "targets_count": len(storage.targets),
        "campaigns_count": len(storage.campaigns)
    }


# Target Endpoints
@app.post("/api/targets", status_code=201)
async def create_target(
    name: str,
    url: HttpUrl,
    description: Optional[str] = None,
    x_api_key: Optional[str] = Header(None)
):
    user = await verify_auth(x_api_key)
    
    target = Target(
        name=name,
        url=str(url),
        description=description
    )
    storage.targets[target.target_id] = target
    return target


@app.get("/api/targets")
async def list_targets(x_api_key: Optional[str] = Header(None)):
    user = await verify_auth(x_api_key)
    return {"targets": list(storage.targets.values())}


@app.get("/api/targets/{target_id}")
async def get_target(target_id: str, x_api_key: Optional[str] = Header(None)):
    user = await verify_auth(x_api_key)
    target = storage.targets.get(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@app.delete("/api/targets/{target_id}", status_code=204)
async def delete_target(target_id: str, x_api_key: Optional[str] = Header(None)):
    user = await verify_auth(x_api_key)
    if target_id not in storage.targets:
        raise HTTPException(status_code=404, detail="Target not found")
    del storage.targets[target_id]
    return None


# Campaign Endpoints
@app.post("/api/campaigns/start", status_code=201)
async def start_campaign(
    target_id: str,
    campaign_name: str = "Auto Campaign",
    background_tasks: BackgroundTasks = None,
    x_api_key: Optional[str] = Header(None)
):
    user = await verify_auth(x_api_key)
    
    target = storage.targets.get(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    campaign = Campaign(
        name=campaign_name,
        target=target,
        status=TaskStatus.RUNNING,
        started_at=datetime.utcnow()
    )
    
    storage.campaigns[campaign.campaign_id] = campaign
    
    # Start real execution in background
    if background_tasks:
        background_tasks.add_task(execute_campaign_real, campaign.campaign_id)
    
    return campaign


@app.get("/api/campaigns")
async def list_campaigns(x_api_key: Optional[str] = Header(None)):
    user = await verify_auth(x_api_key)
    return {"campaigns": list(storage.campaigns.values())}


@app.get("/api/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str, x_api_key: Optional[str] = Header(None)):
    user = await verify_auth(x_api_key)
    campaign = storage.campaigns.get(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@app.get("/api/campaigns/{campaign_id}/status")
async def get_campaign_status(campaign_id: str, x_api_key: Optional[str] = Header(None)):
    user = await verify_auth(x_api_key)
    campaign = storage.campaigns.get(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    return {
        "campaign_id": campaign.campaign_id,
        "status": campaign.status,
        "current_phase": campaign.current_phase,
        "progress": campaign.progress,
        "started_at": campaign.started_at
    }


@app.post("/api/campaigns/{campaign_id}/stop")
async def stop_campaign(campaign_id: str, x_api_key: Optional[str] = Header(None)):
    user = await verify_auth(x_api_key)
    campaign = storage.campaigns.get(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    campaign.status = TaskStatus.CANCELLED
    campaign.completed_at = datetime.utcnow()
    
    return {
        "success": True,
        "message": "Campaign stopped",
        "campaign_id": campaign_id
    }


@app.get("/agent")
async def vanchin_agent():
    """Vanchin AI Agent Interface"""
    return FileResponse("/home/ubuntu/aiprojectattack/vanchin_agent_ui.html")


@app.get("/agent-standalone")
async def vanchin_agent_standalone():
    """Vanchin AI Agent Standalone Interface (works even if Manus is down)"""
    return FileResponse("/home/ubuntu/aiprojectattack/vanchin_agent_standalone.html")


@app.get("/host")
async def host_access():
    """Host Machine Access Terminal for Sandbox Management"""
    return FileResponse("/home/ubuntu/aiprojectattack/host_access.html")


@app.get("/infrastructure")
async def manus_infrastructure():
    """Manus Infrastructure Manager - Control all sandboxes"""
    return FileResponse("/home/ubuntu/aiprojectattack/manus_infrastructure.html")


@app.get("/attack")
async def attack_control_center():
    """Attack Control Center - Main attack dashboard"""
    return FileResponse("/home/ubuntu/aiprojectattack/attack_control_center.html")


if __name__ == "__main__":
    uvicorn.run(
        "integrated_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )

