"""
Integrated Server with PostgreSQL Database
Production-ready server with real database backend
"""

from fastapi import FastAPI, HTTPException, Header, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Dict, Any, List
from datetime import datetime
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session
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
from config.database import get_db, init_database, check_database_connection
from models.database_models import User, APIKey, Target as DBTarget, Campaign as DBCampaign, Task, Vulnerability, UserRole, AttackPhase, TaskStatus, SeverityLevel
import hashlib


# ============================================================================
# Minimal Enums (for compatibility)
# ============================================================================

class AttackPhaseEnum(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"


class TaskStatusEnum(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevelEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ============================================================================
# Data Models (Pydantic for API)
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
    status: TaskStatusEnum = TaskStatusEnum.PENDING
    current_phase: AttackPhaseEnum = AttackPhaseEnum.RECONNAISSANCE
    progress: float = 0.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Helper Functions
# ============================================================================

def hash_api_key(api_key: str) -> str:
    """Hash API key using SHA-256"""
    return hashlib.sha256(api_key.encode()).hexdigest()


async def verify_auth(x_api_key: Optional[str] = Header(None), db: Session = Depends(get_db)):
    """Verify API key from database"""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    
    key_hash = hash_api_key(x_api_key)
    
    # Query database for API key
    db_key = db.query(APIKey).filter(
        APIKey.key_hash == key_hash,
        APIKey.is_active == True
    ).first()
    
    if not db_key:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    # Check if key is expired
    if db_key.expires_at and db_key.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="API Key expired")
    
    # Update last used timestamp
    db_key.last_used_at = datetime.utcnow()
    db.commit()
    
    # Get user information
    user = db.query(User).filter(User.id == db_key.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not active")
    
    return {
        "user_id": user.id,
        "username": user.username,
        "role": db_key.role.value,
        "api_key_id": db_key.id
    }


# ============================================================================
# Real Attack Execution
# ============================================================================

from core.real_campaign_executor import real_campaign_executor

async def execute_campaign_real(campaign_id: str, db: Session):
    """Real campaign execution with actual attack agents"""
    await real_campaign_executor.execute_campaign(campaign_id, db)


# ============================================================================
# FastAPI App
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Integrated Server with PostgreSQL Starting...")
    
    # Check database connection
    if not check_database_connection():
        print("❌ Database connection failed!")
        print("⚠️  Please run: python3 setup_production_database.py")
        yield
        return
    
    print("✅ Database connection successful")
    print("")
    print("🌐 Access the application at:")
    print("   - Frontend: http://localhost:8000/")
    print("   - API Docs: http://localhost:8000/docs")
    yield
    print("👋 Shutting down...")


app = FastAPI(
    title="dLNk Integrated Server with PostgreSQL",
    description="Production backend with PostgreSQL database",
    version="2.0.0",
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
async def health(db: Session = Depends(get_db)):
    # Count records in database
    targets_count = db.query(DBTarget).count()
    campaigns_count = db.query(DBCampaign).count()
    users_count = db.query(User).count()
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0",
        "database": "postgresql",
        "targets_count": targets_count,
        "campaigns_count": campaigns_count,
        "users_count": users_count
    }


# Target Endpoints
@app.post("/api/targets", status_code=201)
async def create_target(
    name: str,
    url: HttpUrl,
    description: Optional[str] = None,
    user: Dict = Depends(verify_auth),
    db: Session = Depends(get_db)
):
    target = DBTarget(
        name=name,
        url=str(url),
        description=description,
        owner_id=user["user_id"]
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    
    return {
        "target_id": target.id,
        "name": target.name,
        "url": target.url,
        "description": target.description,
        "created_at": target.created_at
    }


@app.get("/api/targets")
async def list_targets(
    user: Dict = Depends(verify_auth),
    db: Session = Depends(get_db)
):
    targets = db.query(DBTarget).filter(DBTarget.owner_id == user["user_id"]).all()
    return {
        "targets": [
            {
                "target_id": t.id,
                "name": t.name,
                "url": t.url,
                "description": t.description,
                "created_at": t.created_at
            }
            for t in targets
        ]
    }


@app.get("/api/targets/{target_id}")
async def get_target(
    target_id: str,
    user: Dict = Depends(verify_auth),
    db: Session = Depends(get_db)
):
    target = db.query(DBTarget).filter(
        DBTarget.id == target_id,
        DBTarget.owner_id == user["user_id"]
    ).first()
    
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    return {
        "target_id": target.id,
        "name": target.name,
        "url": target.url,
        "description": target.description,
        "created_at": target.created_at
    }


@app.delete("/api/targets/{target_id}", status_code=204)
async def delete_target(
    target_id: str,
    user: Dict = Depends(verify_auth),
    db: Session = Depends(get_db)
):
    target = db.query(DBTarget).filter(
        DBTarget.id == target_id,
        DBTarget.owner_id == user["user_id"]
    ).first()
    
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    db.delete(target)
    db.commit()
    return None


# Campaign Endpoints
@app.post("/api/campaigns/start", status_code=201)
async def start_campaign(
    target_id: str,
    campaign_name: str = "Auto Campaign",
    background_tasks: BackgroundTasks = None,
    user: Dict = Depends(verify_auth),
    db: Session = Depends(get_db)
):
    target = db.query(DBTarget).filter(
        DBTarget.id == target_id,
        DBTarget.owner_id == user["user_id"]
    ).first()
    
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    campaign = DBCampaign(
        name=campaign_name,
        target_id=target.id,
        owner_id=user["user_id"],
        status=TaskStatus.RUNNING,
        started_at=datetime.utcnow()
    )
    
    db.add(campaign)
    db.commit()
    db.refresh(campaign)
    
    # Start real execution in background
    if background_tasks:
        background_tasks.add_task(execute_campaign_real, campaign.id, db)
    
    return {
        "campaign_id": campaign.id,
        "name": campaign.name,
        "status": campaign.status.value,
        "started_at": campaign.started_at
    }


@app.get("/api/campaigns")
async def list_campaigns(
    user: Dict = Depends(verify_auth),
    db: Session = Depends(get_db)
):
    campaigns = db.query(DBCampaign).filter(DBCampaign.owner_id == user["user_id"]).all()
    return {
        "campaigns": [
            {
                "campaign_id": c.id,
                "name": c.name,
                "status": c.status.value,
                "current_phase": c.current_phase.value,
                "progress": c.progress,
                "started_at": c.started_at
            }
            for c in campaigns
        ]
    }


@app.get("/api/campaigns/{campaign_id}")
async def get_campaign(
    campaign_id: str,
    user: Dict = Depends(verify_auth),
    db: Session = Depends(get_db)
):
    campaign = db.query(DBCampaign).filter(
        DBCampaign.id == campaign_id,
        DBCampaign.owner_id == user["user_id"]
    ).first()
    
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    return {
        "campaign_id": campaign.id,
        "name": campaign.name,
        "status": campaign.status.value,
        "current_phase": campaign.current_phase.value,
        "progress": campaign.progress,
        "started_at": campaign.started_at,
        "completed_at": campaign.completed_at,
        "results": campaign.results
    }


@app.get("/api/campaigns/{campaign_id}/status")
async def get_campaign_status(
    campaign_id: str,
    user: Dict = Depends(verify_auth),
    db: Session = Depends(get_db)
):
    campaign = db.query(DBCampaign).filter(
        DBCampaign.id == campaign_id,
        DBCampaign.owner_id == user["user_id"]
    ).first()
    
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    return {
        "campaign_id": campaign.id,
        "status": campaign.status.value,
        "current_phase": campaign.current_phase.value,
        "progress": campaign.progress,
        "started_at": campaign.started_at
    }


@app.post("/api/campaigns/{campaign_id}/stop")
async def stop_campaign(
    campaign_id: str,
    user: Dict = Depends(verify_auth),
    db: Session = Depends(get_db)
):
    campaign = db.query(DBCampaign).filter(
        DBCampaign.id == campaign_id,
        DBCampaign.owner_id == user["user_id"]
    ).first()
    
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    campaign.status = TaskStatus.CANCELLED
    campaign.completed_at = datetime.utcnow()
    db.commit()
    
    return {
        "success": True,
        "message": "Campaign stopped",
        "campaign_id": campaign_id
    }


# Additional Pages
@app.get("/agent")
async def vanchin_agent():
    """Vanchin AI Agent Interface"""
    return FileResponse("/home/ubuntu/aiprojectattack/vanchin_agent_ui.html")


@app.get("/agent-standalone")
async def vanchin_agent_standalone():
    """Vanchin AI Agent Standalone Interface"""
    return FileResponse("/home/ubuntu/aiprojectattack/vanchin_agent_standalone.html")


@app.get("/host")
async def host_access():
    """Host Machine Access Terminal"""
    return FileResponse("/home/ubuntu/aiprojectattack/host_access.html")


@app.get("/infrastructure")
async def manus_infrastructure():
    """Manus Infrastructure Manager"""
    return FileResponse("/home/ubuntu/aiprojectattack/manus_infrastructure.html")


@app.get("/attack")
async def attack_control_center():
    """Attack Control Center"""
    return FileResponse("/home/ubuntu/aiprojectattack/attack_control_center.html")


if __name__ == "__main__":
    # Initialize database
    init_database()
    
    uvicorn.run(
        "integrated_server_with_db:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )

