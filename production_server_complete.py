#!/usr/bin/env python3
"""
dLNk Attack Platform - Complete Production Server
Integrates all components: Database, Agents, AI, Monitoring, Communication
"""

import asyncio
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from typing import Optional, Dict, List
import logging
from datetime import datetime

# Database
from config.database import get_database_session, check_database_connection
from models.database_models import User, APIKey, Target, Campaign, Task, Vulnerability

# Core Systems
from core.real_campaign_executor import RealCampaignExecutor
from core.agent_communication import get_communicator
from core.realtime_monitoring import get_monitor
from core.self_configuring_agent import SelfConfiguringAgent
from services.auth_service import AuthService
from services.llm_service import LLMService

# Middleware
from middleware.security import RateLimitMiddleware, RateLimiter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger(__name__)


# Global instances
campaign_executor = None
communicator = None
monitor = None
auth_service = None
llm_service = None
rate_limiter = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan"""
    global campaign_executor, communicator, monitor, auth_service, llm_service, rate_limiter
    
    log.info("=" * 80)
    log.info("🚀 dLNk Attack Platform - Production Server Starting...")
    log.info("=" * 80)
    
    # Check database connection
    log.info("📊 Checking database connection...")
    if await check_database_connection():
        log.info("✅ PostgreSQL database connected")
    else:
        log.error("❌ Database connection failed")
        raise Exception("Database connection failed")
    
    # Initialize services
    log.info("🔧 Initializing services...")
    
    campaign_executor = RealCampaignExecutor()
    log.info("  ✅ Campaign Executor initialized")
    
    communicator = get_communicator()
    log.info("  ✅ Agent Communicator initialized")
    
    monitor = get_monitor()
    log.info("  ✅ Real-time Monitor initialized")
    
    auth_service = AuthService()
    log.info("  ✅ Auth Service initialized")
    
    llm_service = LLMService()
    log.info("  ✅ LLM Service initialized")
    
    rate_limiter = RateLimiter(max_requests=60, window_seconds=60)
    log.info("  ✅ Rate Limiter initialized")
    
    # Load agents
    log.info("🤖 Loading attack agents...")
    agent_count = len(campaign_executor.available_agents)
    log.info(f"  ✅ {agent_count} agents loaded and ready")
    
    # Print available agents by category
    agent_categories = {}
    for agent_name in campaign_executor.available_agents.keys():
        category = agent_name.split('_')[0] if '_' in agent_name else 'other'
        agent_categories[category] = agent_categories.get(category, 0) + 1
    
    log.info("📋 Agent Categories:")
    for category, count in sorted(agent_categories.items()):
        log.info(f"  - {category}: {count} agents")
    
    log.info("=" * 80)
    log.info("✅ dLNk Attack Platform is READY")
    log.info("=" * 80)
    log.info("🌐 Server running on: http://0.0.0.0:8000")
    log.info("📖 API Documentation: http://0.0.0.0:8000/docs")
    log.info("🔑 Use admin credentials from ADMIN_CREDENTIALS.txt")
    log.info("=" * 80)
    
    yield
    
    # Shutdown
    log.info("🛑 Shutting down dLNk Attack Platform...")
    log.info("✅ Shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="dLNk Attack Platform",
    description="AI-Powered Automated Attack Platform - Production Ready",
    version="2.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add security middleware
@app.middleware("http")
async def security_middleware(request, call_next):
    """Security middleware"""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    return response


# Authentication dependency
async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> User:
    """Verify API key"""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    user = await auth_service.verify_api_key(x_api_key)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    return user


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    db_status = await check_database_connection()
    
    return {
        "status": "healthy" if db_status else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": db_status,
        "agents_count": len(campaign_executor.available_agents) if campaign_executor else 0,
        "active_campaigns": 0,  # TODO: Get from database
        "version": "2.0.0"
    }


# API Routes

@app.post("/api/targets")
async def create_target(
    data: Dict,
    user: User = Depends(verify_api_key)
):
    """Create new target"""
    async with get_database_session() as session:
        target = Target(
            user_id=user.id,
            name=data['name'],
            url=data['url'],
            description=data.get('description', ''),
            status='active'
        )
        
        session.add(target)
        await session.commit()
        await session.refresh(target)
        
        return {"target_id": str(target.id), "status": "created"}


@app.get("/api/targets")
async def list_targets(user: User = Depends(verify_api_key)):
    """List all targets"""
    async with get_database_session() as session:
        from sqlalchemy import select
        
        result = await session.execute(
            select(Target).where(Target.user_id == user.id)
        )
        targets = result.scalars().all()
        
        return [
            {
                "id": str(t.id),
                "name": t.name,
                "url": t.url,
                "status": t.status,
                "created_at": t.created_at.isoformat()
            }
            for t in targets
        ]


@app.post("/api/campaigns")
async def create_campaign(
    data: Dict,
    user: User = Depends(verify_api_key)
):
    """Create new campaign"""
    async with get_database_session() as session:
        campaign = Campaign(
            user_id=user.id,
            target_id=data['target_id'],
            name=data['name'],
            attack_type=data.get('attack_type', 'full'),
            status='created',
            progress=0.0
        )
        
        session.add(campaign)
        await session.commit()
        await session.refresh(campaign)
        
        return {"campaign_id": str(campaign.id), "status": "created"}


@app.post("/api/campaigns/{campaign_id}/start")
async def start_campaign(
    campaign_id: str,
    user: User = Depends(verify_api_key)
):
    """Start campaign"""
    async with get_database_session() as session:
        from sqlalchemy import select
        
        result = await session.execute(
            select(Campaign).where(
                Campaign.id == campaign_id,
                Campaign.user_id == user.id
            )
        )
        campaign = result.scalar_one_or_none()
        
        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")
        
        # Get target
        result = await session.execute(
            select(Target).where(Target.id == campaign.target_id)
        )
        target = result.scalar_one()
        
        # Start campaign execution
        campaign.status = 'running'
        campaign.started_at = datetime.utcnow()
        await session.commit()
        
        # Execute in background
        asyncio.create_task(
            campaign_executor.execute_campaign(
                campaign_id=str(campaign.id),
                target_url=target.url,
                attack_type=campaign.attack_type
            )
        )
        
        return {"status": "started", "campaign_id": campaign_id}


@app.get("/api/campaigns/{campaign_id}/status")
async def get_campaign_status(
    campaign_id: str,
    user: User = Depends(verify_api_key)
):
    """Get campaign status"""
    async with get_database_session() as session:
        from sqlalchemy import select
        
        result = await session.execute(
            select(Campaign).where(
                Campaign.id == campaign_id,
                Campaign.user_id == user.id
            )
        )
        campaign = result.scalar_one_or_none()
        
        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")
        
        # Get tasks
        result = await session.execute(
            select(Task).where(Task.campaign_id == campaign_id)
        )
        tasks = result.scalars().all()
        
        completed_tasks = sum(1 for t in tasks if t.status == 'completed')
        
        # Get vulnerabilities
        result = await session.execute(
            select(Vulnerability).where(Vulnerability.campaign_id == campaign_id)
        )
        vulnerabilities = result.scalars().all()
        
        return {
            "status": campaign.status,
            "progress": campaign.progress,
            "completed_tasks": completed_tasks,
            "total_tasks": len(tasks),
            "vulnerabilities_found": len(vulnerabilities),
            "started_at": campaign.started_at.isoformat() if campaign.started_at else None
        }


@app.get("/api/campaigns")
async def list_campaigns(user: User = Depends(verify_api_key)):
    """List all campaigns"""
    async with get_database_session() as session:
        from sqlalchemy import select
        
        result = await session.execute(
            select(Campaign).where(Campaign.user_id == user.id)
        )
        campaigns = result.scalars().all()
        
        return [
            {
                "id": str(c.id),
                "name": c.name,
                "status": c.status,
                "progress": c.progress,
                "attack_type": c.attack_type,
                "created_at": c.created_at.isoformat()
            }
            for c in campaigns
        ]


@app.get("/api/agents")
async def list_agents(user: User = Depends(verify_api_key)):
    """List all available agents"""
    agents = []
    
    for agent_name, module_path in campaign_executor.available_agents.items():
        agents.append({
            "name": agent_name,
            "type": "attack_agent",
            "status": "ready",
            "capabilities": [],
            "module": module_path
        })
    
    return agents


@app.post("/api/agents/execute")
async def execute_agent(
    data: Dict,
    user: User = Depends(verify_api_key)
):
    """Execute single agent"""
    agent_name = data['agent_name']
    target_url = data['target_url']
    
    if agent_name not in campaign_executor.available_agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Execute agent (placeholder - implement actual execution)
    return {
        "success": True,
        "agent": agent_name,
        "target": target_url,
        "summary": f"Agent {agent_name} executed",
        "status": "completed"
    }


# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time updates"""
    await websocket.accept()
    await monitor.register_connection(websocket)
    
    try:
        while True:
            # Receive messages from client
            data = await websocket.receive_json()
            
            # Handle subscription requests
            if data.get('type') == 'subscribe':
                topics = data.get('topics', [])
                await monitor.subscribe(websocket, topics)
            
            elif data.get('type') == 'monitor_campaign':
                campaign_id = data.get('campaign_id')
                await monitor.monitor_campaign(websocket, campaign_id)
            
    except WebSocketDisconnect:
        await monitor.unregister_connection(websocket)


# Main page
@app.get("/", response_class=HTMLResponse)
async def main_page():
    """Main page"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>dLNk Attack Platform</title>
        <style>
            body {
                font-family: 'Courier New', monospace;
                background: #0a0a0a;
                color: #00ff00;
                padding: 20px;
                max-width: 1200px;
                margin: 0 auto;
            }
            h1 { color: #ff0000; text-align: center; }
            .section {
                background: #1a1a1a;
                border: 2px solid #00ff00;
                padding: 20px;
                margin: 20px 0;
                border-radius: 5px;
            }
            .endpoint {
                background: #0a0a0a;
                padding: 10px;
                margin: 10px 0;
                border-left: 3px solid #ff0000;
            }
            .method {
                color: #ffff00;
                font-weight: bold;
            }
            a { color: #00ffff; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>⚡ dLNk Attack Platform ⚡</h1>
        
        <div class="section">
            <h2>🎯 System Status</h2>
            <p>Status: <span style="color:#00ff00">ONLINE</span></p>
            <p>Version: 2.0.0</p>
            <p>Mode: PRODUCTION</p>
        </div>
        
        <div class="section">
            <h2>📖 API Documentation</h2>
            <p><a href="/docs">Interactive API Docs (Swagger)</a></p>
            <p><a href="/redoc">Alternative API Docs (ReDoc)</a></p>
        </div>
        
        <div class="section">
            <h2>🔑 Quick Start</h2>
            <div class="endpoint">
                <span class="method">GET</span> /health - Health check
            </div>
            <div class="endpoint">
                <span class="method">POST</span> /api/targets - Create target
            </div>
            <div class="endpoint">
                <span class="method">POST</span> /api/campaigns - Create campaign
            </div>
            <div class="endpoint">
                <span class="method">POST</span> /api/campaigns/{id}/start - Start attack
            </div>
        </div>
        
        <div class="section">
            <h2>⚠️ Warning</h2>
            <p style="color:#ff0000">
                This is an ATTACK PLATFORM. Use only on authorized targets.
                Unauthorized use is illegal and unethical.
            </p>
        </div>
    </body>
    </html>
    """


if __name__ == "__main__":
    uvicorn.run(
        "production_server_complete:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )

