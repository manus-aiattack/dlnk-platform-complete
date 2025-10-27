#!/usr/bin/env python3
"""
dLNk Attack Platform - Production Runner (Fixed)
Runs the complete system with all 163 Agents and full API endpoints
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Load .env file
from dotenv import load_dotenv
load_dotenv()

# Set environment variables
os.environ.setdefault("VC_API_KEY", "8-WmOAVImJdRrqBybLj55n-QDu1Y-WYnQNRb280wLhU")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("DATABASE_URL", "postgresql://dlnk:dlnk_password@localhost:5432/dlnk")
os.environ.setdefault("DB_PREFERENCE", "postgresql")
os.environ.setdefault("PYTHONUNBUFFERED", "1")

import uvicorn
from fastapi.responses import HTMLResponse

print("=" * 80)
print("dLNk Attack Platform - Production Mode")
print("=" * 80)
print("Loading API with 163 Agents and Attack Orchestrator...")

# Import the complete API directly (don't mount it)
try:
    from api.main import app
    print("[✓] API loaded successfully with all endpoints")
except Exception as e:
    print(f"[✗] Failed to load API: {e}")
    from fastapi import FastAPI
    app = FastAPI(title="dLNk Attack Platform - Fallback")

# Add frontend routes to the same app
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

