#!/usr/bin/env python3
"""
dLNk Attack Platform - Production Runner
Runs the complete system with all 163 Agents and full API endpoints
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Set environment variables
os.environ.setdefault("VC_API_KEY", "8-WmOAVImJdRrqBybLj55n-QDu1Y-WYnQNRb280wLhU")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("DATABASE_URL", "postgresql://dlnk_user:dlnk_password@localhost/dlnk_attack_db")
os.environ.setdefault("PYTHONUNBUFFERED", "1")

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

print("=" * 80)
print("dLNk Attack Platform - Production Mode")
print("=" * 80)
print("Loading API with 163 Agents and Attack Orchestrator...")

# Import the complete API
try:
    from api.main import app as api_app
    print("[✓] API loaded successfully with all endpoints")
except Exception as e:
    print(f"[✗] Failed to load API: {e}")
    print("Creating minimal fallback...")
    api_app = FastAPI(title="dLNk Attack Platform - Fallback")

# Create wrapper app
app = FastAPI(
    title="dLNk Attack Platform",
    description="AI-Powered Autonomous Attack Platform with 163+ Agents",
    version="3.0.0-production",
    docs_url=None,  # Disable root docs
    redoc_url=None
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
        with open("frontend_hacker.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except Exception as e:
        return HTMLResponse(content=f"<h1>dLNk Attack Platform</h1><p>Error: {e}</p>")

@app.get("/admin", response_class=HTMLResponse)
async def serve_admin():
    """Serve admin panel"""
    try:
        with open("admin_panel.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except Exception as e:
        return HTMLResponse(content=f"<h1>Admin Panel</h1><p>Error: {e}</p>")

# Mount complete API
app.mount("/api", api_app)

# Root health check
@app.get("/health")
async def health():
    return {
        "status": "operational",
        "platform": "dLNk Attack Platform",
        "agents": 163,
        "version": "3.0.0-production"
    }

if __name__ == "__main__":
    print("=" * 80)
    print("Starting Production Server...")
    print("=" * 80)
    print("Frontend:    http://0.0.0.0:8000/")
    print("Admin Panel: http://0.0.0.0:8000/admin")
    print("API Docs:    http://0.0.0.0:8000/api/docs")
    print("Health:      http://0.0.0.0:8000/health")
    print("=" * 80)
    print("Admin Key: admin_key_001")
    print("=" * 80)
    
    # Run with uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True
    )

