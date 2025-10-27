"""
Test API Server with Working Endpoints
Uses mock services for testing without actual attacks
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
import uvicorn
from datetime import datetime

# Production services
from config.database import get_database_session
from services.real_attack_executor import RealAttackExecutor
from api.services.websocket_manager import WebSocketManager
from services.auth_service import AuthService

# Import improved routes
from api.routes import attack_improved

# Initialize services
ws_manager = WebSocketManager()
attack_executor = RealAttackExecutor()
auth_service = AuthService()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    print("[API] Starting dLNk Attack Platform Production Server...")
    print("[API] PostgreSQL database connected")
    print("[API] Production API Keys loaded from database")
    print("[API] Use admin credentials from ADMIN_CREDENTIALS.txt")
    
    yield
    
    # Shutdown
    print("[API] Shutting down...")
    await db.disconnect()


# Create FastAPI app
app = FastAPI(
    title="dLNk Attack Platform API - Test Server",
    description="Test server with working endpoints using mock services",
    version="4.0.0-test",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Root endpoint
@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>dLNk Test Server</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
                color: #e0e0e0;
                padding: 40px;
                margin: 0;
            }
            .container {
                max-width: 1200px;
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
            .info-box {
                background: rgba(10, 14, 39, 0.8);
                border: 1px solid rgba(0, 255, 136, 0.3);
                border-radius: 10px;
                padding: 20px;
                margin: 20px 0;
            }
            .info-box h3 {
                color: #00ff88;
                margin-top: 0;
            }
            .api-key {
                background: rgba(0, 0, 0, 0.5);
                padding: 10px;
                border-radius: 5px;
                font-family: monospace;
                margin: 5px 0;
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
            code {
                background: rgba(0, 0, 0, 0.5);
                padding: 2px 6px;
                border-radius: 3px;
                color: #00ff88;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🧪 dLNk Test Server</h1>
            <p class="subtitle">Development & Testing Environment with Mock Services</p>
            
            <div style="text-align: center;">
                <span class="status">🟢 TEST MODE ACTIVE</span>
            </div>
            
            <div class="info-box">
                <h3>📋 Test API Keys</h3>
                <p>Use these API keys in the <code>X-API-Key</code> header:</p>
                <div class="api-key">
                    <strong>Admin:</strong> admin_test_key_12345
                </div>
                <div class="api-key">
                    <strong>User:</strong> user_test_key_67890
                </div>
            </div>
            
            <div class="info-box">
                <h3>✨ Available Features</h3>
                <ul>
                    <li>✅ Target Management (Create, List, Get, Delete)</li>
                    <li>✅ Attack Campaigns (Start, Stop, Status, Results)</li>
                    <li>✅ Mock Reconnaissance, Vulnerability Scanning, Exploitation</li>
                    <li>✅ WebSocket Real-time Updates</li>
                    <li>✅ User Authentication & Authorization</li>
                    <li>✅ Unified Data Models with Pydantic Validation</li>
                </ul>
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
                
                <a href="/api/v2/attack/campaigns" class="link-card">
                    <div class="link-icon">⚔️</div>
                    <div class="link-title">Campaigns</div>
                    <div class="link-desc">Attack campaigns</div>
                </a>
                
                <a href="/api/v2/attack/targets" class="link-card">
                    <div class="link-icon">🎯</div>
                    <div class="link-title">Targets</div>
                    <div class="link-desc">Target management</div>
                </a>
            </div>
            
            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid rgba(255, 255, 255, 0.1); text-align: center; color: #b0b0b0; font-size: 14px;">
                <p>dLNk Attack Platform v4.0.0 - Test Server</p>
                <p>⚠️ This is a test environment with mock services - No actual attacks are performed</p>
            </div>
        </div>
    </body>
    </html>
    """


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "database": await db.health_check(),
        "timestamp": datetime.now().isoformat(),
        "version": "4.0.0-test",
        "mode": "testing"
    }


# Statistics endpoint
@app.get("/api/stats")
async def get_statistics():
    """Get system statistics"""
    stats = await db.get_statistics()
    return {
        "timestamp": datetime.now().isoformat(),
        "statistics": stats
    }


# WebSocket endpoint
@app.websocket("/ws/system")
async def websocket_system(websocket: WebSocket):
    """WebSocket for system monitoring"""
    await ws_manager.connect_system(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({
                "type": "pong",
                "timestamp": datetime.now().isoformat()
            })
    except WebSocketDisconnect:
        ws_manager.disconnect_system(websocket)


# Set dependencies for improved routes
attack_improved.set_dependencies(db, ws_manager, attack_manager, auth_service)

# Include improved routes
app.include_router(attack_improved.router)


if __name__ == "__main__":
    uvicorn.run(
        "test_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

