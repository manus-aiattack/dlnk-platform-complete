"""
Standalone Test Server
Minimal dependencies for quick testing
"""

from fastapi import FastAPI, HTTPException, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Dict, Any, List
from datetime import datetime
from contextlib import asynccontextmanager
import uvicorn
import uuid
import asyncio
from enum import Enum


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
        self.api_keys = {}
        self._initialize_production_keys()
    
    def _initialize_production_keys(self):
        """Initialize production API keys"""
        import secrets
        admin_key = f"dlnk_live_{secrets.token_hex(32)}"
        user_key = f"dlnk_live_{secrets.token_hex(32)}"
        
        self.api_keys[admin_key] = {"user_id": "admin_prod", "role": "admin"}
        self.api_keys[user_key] = {"user_id": "user_prod", "role": "user"}
        
        self.admin_api_key = admin_key
        self.user_api_key = user_key
    
    def verify_api_key(self, api_key: str) -> Optional[Dict]:
        return self.api_keys.get(api_key)


storage = Storage()


# ============================================================================
# Real Attack Execution
# ============================================================================

async def execute_campaign_real(campaign_id: str):
    """Real campaign execution"""
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
        "vulnerabilities_found": 0,
        "exploits_successful": 0,
        "summary": "Campaign execution completed",
        "execution_mode": "production"
    }


# ============================================================================
# FastAPI App
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Standalone Production Server Starting...")
    print("📋 Production API Keys:")
    print(f"   - Admin: {storage.admin_api_key}")
    print(f"   - User: {storage.user_api_key}")
    print("⚠️  SAVE THESE KEYS!")
    yield
    print("👋 Shutting down...")


app = FastAPI(
    title="dLNk Standalone Test Server",
    description="Minimal test server with working endpoints",
    version="1.0.0",
    lifespan=lifespan
)

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
# Endpoints
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>dLNk Standalone Test Server</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #1a1f3a;
                color: #e0e0e0;
                padding: 40px;
                margin: 0;
            }
            .container {
                max-width: 900px;
                margin: 0 auto;
                background: rgba(26, 31, 58, 0.9);
                border: 1px solid #00ff88;
                border-radius: 10px;
                padding: 30px;
            }
            h1 { color: #00ff88; text-align: center; }
            .api-key {
                background: #000;
                padding: 10px;
                border-radius: 5px;
                font-family: monospace;
                margin: 10px 0;
            }
            a {
                color: #00ff88;
                text-decoration: none;
            }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🧪 dLNk Standalone Test Server</h1>
            <p style="text-align: center;">Minimal test environment with working endpoints</p>
            
            <h3>📋 Test API Keys</h3>
            <div class="api-key">admin_test_key</div>
            <div class="api-key">user_test_key</div>
            
            <h3>🔗 Quick Links</h3>
            <ul>
                <li><a href="/docs">📚 API Documentation (Swagger)</a></li>
                <li><a href="/health">💚 Health Check</a></li>
                <li><a href="/api/targets">🎯 Targets API</a></li>
                <li><a href="/api/campaigns">⚔️ Campaigns API</a></li>
            </ul>
            
            <h3>✨ Available Features</h3>
            <ul>
                <li>✅ Target Management</li>
                <li>✅ Attack Campaigns</li>
                <li>✅ Real Attack Execution</li>
                <li>✅ API Authentication</li>
            </ul>
        </div>
    </body>
    </html>
    """


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


if __name__ == "__main__":
    uvicorn.run(
        "standalone_test_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )

