#!/usr/bin/env python3
"""
dLNk Attack Platform - Production Server
Integrates all components with full Agent support
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Set environment
os.environ.setdefault("VC_API_KEY", "8-WmOAVImJdRrqBybLj55n-QDu1Y-WYnQNRb280wLhU")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("DATABASE_URL", "postgresql://dlnk_user:dlnk_password@localhost/dlnk_attack_db")

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Import existing API
try:
    from api.main import app as api_app
    print("[OK] API loaded successfully")
except Exception as e:
    print(f"[ERROR] Failed to load API: {e}")
    # Create minimal app
    api_app = FastAPI(title="dLNk Attack Platform")

# Create main app
app = FastAPI(
    title="dLNk Attack Platform - Production",
    description="AI-Powered Autonomous Attack Platform with 163+ Agents",
    version="3.0.0-production"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve Frontend
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve main frontend"""
    try:
        with open("frontend_hacker.html", "r") as f:
            return HTMLResponse(content=f.read())
    except:
        return HTMLResponse(content="<h1>dLNk Attack Platform</h1><p>Frontend not found</p>")

@app.get("/admin", response_class=HTMLResponse)
async def serve_admin():
    """Serve admin panel"""
    try:
        with open("admin_panel.html", "r") as f:
            return HTMLResponse(content=f.read())
    except:
        return HTMLResponse(content="<h1>Admin Panel</h1><p>Admin panel not found</p>")

# Mount API
app.mount("/api", api_app)

# Health check
@app.get("/health")
async def health():
    return {"status": "operational", "platform": "dLNk Attack Platform"}

if __name__ == "__main__":
    print("=" * 70)
    print("dLNk Attack Platform - Production Server")
    print("=" * 70)
    print("Frontend: http://0.0.0.0:8000/")
    print("Admin Panel: http://0.0.0.0:8000/admin")
    print("API: http://0.0.0.0:8000/api/")
    print("API Docs: http://0.0.0.0:8000/api/docs")
    print("=" * 70)
    print("Admin Key: admin_key_001")
    print("=" * 70)
    
    uvicorn.run(
        "production_server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )

