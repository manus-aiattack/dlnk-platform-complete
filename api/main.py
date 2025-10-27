"""
dLNk Attack Platform - Complete API Server
Integrates ALL routes and features from all main files
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from fastapi.responses import HTMLResponse, FileResponse
from contextlib import asynccontextmanager
import uvicorn
import asyncio
from typing import List, Dict, Any
from datetime import datetime
import os

# Services
from api.services.database import Database
from api.services.auth import AuthService
from api.services.attack_manager import AttackManager
from api.services.websocket_manager import WebSocketManager
from core.logger import log

# Import ALL routes
from api.routes import (
    auth, admin, attack, files,  # v1 routes
    admin_v2, attack_v2,  # v2 routes
    ai, scan, exploit, knowledge, statistics,  # feature routes
    c2, c2_shell, fuzzing, learning_routes, one_click_attack, zeroday_routes, monitoring, workflow,  # additional routes
    vanchin_chat,  # Vanchin AI Chat
    vanchin_agent  # Vanchin AI Agent
)

# WebSocket Manager
ws_manager = WebSocketManager()

# Database
db = Database()

# Services
auth_service = AuthService(db)
attack_manager = AttackManager(db, ws_manager)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    log.info("[API] Starting dLNk Attack Platform API (Complete Edition)...")
    try:
        await db.connect()
        log.success("[API] Database connected")
    except Exception as e:
        log.warning(f"[API] Database connection failed: {e}")
        log.info("[API] Running without database (development mode)")
    
    yield
    
    # Shutdown
    log.info("[API] Shutting down...")
    try:
        await db.disconnect()
        log.info("[API] Database disconnected")
    except:
        pass


# Create FastAPI app
app = FastAPI(
    title="dLNk Attack Platform API - Complete Edition",
    description="Advanced Penetration Testing Platform with AI-powered Zero-Day Discovery - All Features Integrated",
    version="3.0.0-complete",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# API Key Header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Depends(api_key_header)):
    """Verify API key"""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key required"
        )
    
    user = await auth_service.verify_key(api_key)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key"
        )
    
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API Key is disabled"
        )
    
    return user


async def verify_admin(user: Dict = Depends(verify_api_key)):
    """Verify admin role"""
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return user


# Root endpoint with beautiful HTML
@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>dLNk Attack Platform API</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
                color: #e0e0e0;
                padding: 40px;
                margin: 0;
            }
            .container {
                max-width: 1000px;
                margin: 0 auto;
                background: rgba(26, 31, 58, 0.8);
                border: 1px solid rgba(0, 255, 136, 0.3);
                border-radius: 15px;
                padding: 40px;
            }
            h1 {
                color: #00ff88;
                text-align: center;
                font-size: 36px;
                margin-bottom: 10px;
            }
            .subtitle {
                text-align: center;
                color: #b0b0b0;
                margin-bottom: 40px;
            }
            .links {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-top: 30px;
            }
            .link-card {
                background: rgba(10, 14, 39, 0.8);
                border: 1px solid rgba(0, 255, 136, 0.3);
                border-radius: 10px;
                padding: 20px;
                text-align: center;
                text-decoration: none;
                color: #e0e0e0;
                transition: all 0.3s ease;
            }
            .link-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 30px rgba(0, 255, 136, 0.3);
                border-color: #00ff88;
            }
            .link-icon {
                font-size: 48px;
                margin-bottom: 10px;
            }
            .link-title {
                font-size: 18px;
                font-weight: bold;
                color: #00ff88;
                margin-bottom: 5px;
            }
            .link-desc {
                font-size: 14px;
                color: #b0b0b0;
            }
            .status {
                background: rgba(0, 255, 136, 0.2);
                border: 1px solid #00ff88;
                border-radius: 20px;
                padding: 8px 16px;
                display: inline-block;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎯 dLNk Attack Platform API</h1>
            <p class="subtitle">Advanced AI-Driven Penetration Testing Framework - Complete Edition v3.0.0</p>
            
            <div style="text-align: center;">
                <span class="status">🟢 ALL SYSTEMS OPERATIONAL</span>
            </div>
            
            <div class="links">
                <a href="/docs" class="link-card">
                    <div class="link-icon">📚</div>
                    <div class="link-title">API Documentation</div>
                    <div class="link-desc">Interactive Swagger UI</div>
                </a>
                
                <a href="/health" class="link-card">
                    <div class="link-icon">💚</div>
                    <div class="link-title">Health Check</div>
                    <div class="link-desc">System status</div>
                </a>
                
                <a href="/api/status" class="link-card">
                    <div class="link-icon">📊</div>
                    <div class="link-title">System Status</div>
                    <div class="link-desc">Detailed metrics</div>
                </a>
            </div>
            
            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid rgba(255, 255, 255, 0.1); text-align: center; color: #b0b0b0; font-size: 14px;">
                <p>dLNk Attack Platform v3.0.0 - Complete Edition</p>
                <p>© 2024 dLNk Team. All rights reserved.</p>
                <p style="margin-top: 10px; font-size: 12px;">
                    ⚠️ Authorized Use Only - Unauthorized access is illegal
                </p>
            </div>
        </div>
    </body>
    </html>
    """


# Dashboard
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Main dashboard"""
    with open("/home/ubuntu/aiprojectattack/dashboard.html") as f:
        return f.read()


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "database": await db.health_check(),
        "timestamp": datetime.now().isoformat(),
        "version": "3.0.0-complete"
    }


# System status endpoint
@app.get("/api/status")
async def get_system_status():
    """Get detailed system status"""
    import psutil
    
    try:
        import ollama
        models = ollama.list()
        llm_status = {
            "available": True,
            "models": [model["name"] for model in models.get("models", [])],
            "count": len(models.get("models", []))
        }
    except Exception as e:
        llm_status = {
            "available": False,
            "error": str(e)
        }
    
    # CPU and Memory
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # Active attacks
    try:
        active_attacks = await db.get_active_attacks_count()
    except:
        active_attacks = 0
    
    return {
        "timestamp": datetime.now().isoformat(),
        "version": "3.0.0-complete",
        "system": {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_used_gb": round(memory.used / (1024**3), 2),
            "memory_total_gb": round(memory.total / (1024**3), 2),
            "disk_percent": disk.percent,
            "disk_used_gb": round(disk.used / (1024**3), 2),
            "disk_total_gb": round(disk.total / (1024**3), 2)
        },
        "llm": llm_status,
        "database": {
            "connected": await db.health_check(),
            "active_attacks": active_attacks
        }
    }


# WebSocket endpoints
@app.websocket("/ws/attack/{attack_id}")
async def websocket_attack(websocket: WebSocket, attack_id: str):
    """WebSocket for real-time attack updates"""
    await ws_manager.connect(websocket, attack_id)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, attack_id)


@app.websocket("/ws/system")
async def websocket_system(websocket: WebSocket):
    """WebSocket for system monitoring"""
    await ws_manager.connect_system(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "system_status", "data": await get_system_status()})
    except WebSocketDisconnect:
        ws_manager.disconnect_system(websocket)


@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """WebSocket for live log monitoring"""
    await ws_manager.connect_logs(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # For now, just send a ping response
            await websocket.send_json({"type": "log_pong", "timestamp": datetime.now().isoformat()})
    except WebSocketDisconnect:
        ws_manager.disconnect_logs(websocket)


@app.websocket("/ws")
async def websocket_general(websocket: WebSocket):
    """General WebSocket endpoint"""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "pong", "message": "Connected to dLNk Attack Platform"})
    except WebSocketDisconnect:
        pass


# Set dependencies for v1 routers
auth.set_dependencies(db, auth_service)
admin.set_dependencies(db, auth_service)
attack.set_dependencies(db, ws_manager, attack_manager, auth_service)
files.set_dependencies(db, auth_service)
workflow.set_dependencies(db, auth_service)

# Include ALL routers
# V1 Routes
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(admin.router, prefix="/api/admin", tags=["Admin"], dependencies=[Depends(verify_admin)])
app.include_router(attack.router, prefix="/api/attack", tags=["Attack V1"], dependencies=[Depends(verify_api_key)])
app.include_router(files.router, prefix="/api/files", tags=["Files"], dependencies=[Depends(verify_api_key)])
app.include_router(workflow.router, tags=["Workflow"])  # No auth required for testing

# V2 Routes (with their own prefixes)
app.include_router(attack_v2.router, tags=["Attack V2"])
app.include_router(admin_v2.router, tags=["Admin V2"])

# Feature Routes
app.include_router(ai.router, tags=["AI"])
app.include_router(scan.router, tags=["Scan"])
app.include_router(exploit.router, tags=["Exploit"])
app.include_router(knowledge.router, tags=["Knowledge"])
app.include_router(statistics.router, tags=["Statistics"])
app.include_router(c2.router, tags=["C2 Server"])
app.include_router(c2_shell.router, tags=["C2 Shell"])
app.include_router(fuzzing.router, tags=["Fuzzing"])
app.include_router(learning_routes.router, tags=["Learning"])
app.include_router(one_click_attack.router, tags=["One-Click Attack"])
app.include_router(zeroday_routes.router, tags=["Zero-Day"])
app.include_router(monitoring.router, tags=["Monitoring"])
app.include_router(vanchin_chat.router, tags=["Vanchin Chat"])
app.include_router(vanchin_agent.router, tags=["Vanchin Agent"])


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )


# Vanchin Chat Interface
@app.get("/chat")
async def vanchin_chat_interface():
    """Serve Vanchin Chat Interface"""
    from fastapi.responses import FileResponse
    return FileResponse("/home/ubuntu/aiprojectattack/vanchin_chat.html")
