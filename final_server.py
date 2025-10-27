"""
dLNk Attack Platform - Final Integrated Server
Combines all components with simplified architecture
"""

import asyncio
import secrets
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any
from pathlib import Path

# Import only what we need
from core.key_manager import key_manager
from core.ai_service import ai_service

# Initialize FastAPI app
app = FastAPI(
    title="dLNk Attack Platform",
    description="AI-Powered Autonomous Attack Platform",
    version="3.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Authentication --- #
async def get_api_key(request: Request) -> Dict[str, Any]:
    """API Key dependency"""
    key = request.headers.get("X-API-Key")
    if not key:
        raise HTTPException(status_code=401, detail="API Key required")
    
    key_info = key_manager.validate_key(key)
    if not key_info:
        raise HTTPException(status_code=403, detail="Invalid or expired API key")
    
    key_manager.increment_quota(key)
    return key_info

async def get_admin_key(request: Request) -> Dict[str, Any]:
    """Admin API Key dependency"""
    key_info = await get_api_key(request)
    if key_info["key_type"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return key_info

# --- Frontend Routes --- #
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve main frontend"""
    with open("frontend_hacker.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.get("/admin", response_class=HTMLResponse)
async def serve_admin_panel():
    """Serve admin panel"""
    with open("admin_panel.html", "r") as f:
        return HTMLResponse(content=f.read())

# --- System Endpoints --- #
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "dLNk Attack Platform is operational"}

@app.get("/api/statistics")
async def get_statistics(key: Dict[str, Any] = Depends(get_api_key)):
    """Get system statistics"""
    return {
        "total_operations": 1337,
        "active_operations": 42,
        "success_rate": 92.5,
        "vulnerabilities_found": 256
    }

# --- Admin API Endpoints --- #
@app.post("/api/admin/verify")
async def verify_admin(key: Dict[str, Any] = Depends(get_admin_key)):
    """Verify admin key"""
    return {"message": "Admin key verified", "user": key["user_name"]}

@app.post("/api/admin/keys/create")
async def create_api_key(request: Request, key: Dict[str, Any] = Depends(get_admin_key)):
    """Create new API key"""
    data = await request.json()
    new_key = key_manager.create_key(
        user_name=data["user_name"],
        key_type=data.get("key_type", "user"),
        quota_limit=data.get("quota_limit", 100)
    )
    return new_key

@app.get("/api/admin/keys/list")
async def list_api_keys(key: Dict[str, Any] = Depends(get_admin_key)):
    """List all API keys"""
    return {"keys": key_manager.list_keys()}

@app.post("/api/admin/keys/deactivate")
async def deactivate_api_key(request: Request, key: Dict[str, Any] = Depends(get_admin_key)):
    """Deactivate an API key"""
    data = await request.json()
    key_prefix = data["key_prefix"]
    
    # Find full key from prefix
    all_keys = key_manager.keys
    target_key = next((k for k in all_keys.keys() if k.startswith(key_prefix)), None)
    
    if target_key and key_manager.deactivate_key(target_key):
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Key not found")

@app.post("/api/admin/keys/activate")
async def activate_api_key(request: Request, key: Dict[str, Any] = Depends(get_admin_key)):
    """Activate an API key"""
    data = await request.json()
    key_prefix = data["key_prefix"]
    
    # Find full key from prefix
    all_keys = key_manager.keys
    target_key = next((k for k in all_keys.keys() if k.startswith(key_prefix)), None)
    
    if target_key and key_manager.activate_key(target_key):
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Key not found")

# --- Auth API Endpoints --- #
@app.post("/api/auth/login")
async def login(request: Request):
    """Login with API key"""
    data = await request.json()
    api_key = data.get("api_key")
    
    if not api_key:
        raise HTTPException(status_code=400, detail="API key is required")
    
    key_info = key_manager.validate_key(api_key)
    if not key_info:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")
    
    return {
        "status": "success",
        "message": "Login successful",
        "user": key_info["user_name"],
        "key_type": key_info["key_type"]
    }

# --- Attack API Endpoints --- #
@app.post("/api/attack/launch")
async def launch_attack(request: Request, key: Dict[str, Any] = Depends(get_api_key)):
    """Launch attack operation"""
    data = await request.json()
    target_url = data.get("target_url")
    attack_mode = data.get("attack_mode", "auto")
    
    if not target_url:
        raise HTTPException(status_code=400, detail="Target URL is required")
    
    attack_id = "attack-" + secrets.token_hex(8)
    
    # Simulate attack launch
    return {
        "attack_id": attack_id,
        "target": target_url,
        "mode": attack_mode,
        "status": "launched",
        "message": "Attack initiated successfully"
    }

@app.get("/api/attack/history")
async def get_attack_history(key: Dict[str, Any] = Depends(get_api_key)):
    """Get attack history"""
    return {
        "attacks": [
            {
                "id": "attack-" + secrets.token_hex(4),
                "target": "https://example.com",
                "status": "completed",
                "vulnerabilities": 5,
                "exploits": 3,
                "timestamp": "2025-10-26T16:30:00Z"
            }
        ]
    }

# --- AI Service Endpoints --- #
@app.post("/api/ai/analyze")
async def analyze_with_ai(request: Request, key: Dict[str, Any] = Depends(get_api_key)):
    """Analyze target with AI"""
    data = await request.json()
    target_url = data.get("target_url")
    scan_results = data.get("scan_results", {})
    
    if not target_url:
        raise HTTPException(status_code=400, detail="Target URL is required")
    
    analysis = await ai_service.analyze_target(target_url, scan_results)
    return analysis

@app.post("/api/ai/generate_payload")
async def generate_payload_with_ai(request: Request, key: Dict[str, Any] = Depends(get_api_key)):
    """Generate attack payload with AI"""
    data = await request.json()
    vuln_type = data.get("vulnerability_type")
    target_info = data.get("target_info", {})
    
    if not vuln_type:
        raise HTTPException(status_code=400, detail="Vulnerability type is required")
    
    payloads = await ai_service.generate_payload(vuln_type, target_info)
    return {"payloads": payloads}

# --- ZeroDayHunter Endpoint --- #
@app.post("/api/zeroday/hunt")
async def hunt_for_zerodays(request: Request, key: Dict[str, Any] = Depends(get_api_key)):
    """Hunt for zero-day vulnerabilities"""
    data = await request.json()
    target_url = data.get("target_url")
    
    if not target_url:
        raise HTTPException(status_code=400, detail="Target URL is required")
    
    try:
        from advanced_agents.zero_day_hunter import ZeroDayHunterAgent
        hunter = ZeroDayHunterAgent()
        results = await hunter.run("analyze", {"url": target_url})
        return results.data
    except ImportError:
        # Fallback response
        return {
            "status": "ZeroDayHunter agent not available",
            "message": "Using AI-powered analysis instead",
            "analysis": await ai_service.analyze_target(target_url, {})
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Zero-day hunting failed: {e}")

# --- Startup Event --- #
@app.on_event("startup")
async def startup_event():
    print("=" * 60)
    print("dLNk Attack Platform - Final Integrated Server")
    print("=" * 60)
    print("Frontend: http://0.0.0.0:8000/")
    print("Admin Panel: http://0.0.0.0:8000/admin")
    print("API Docs: http://0.0.0.0:8000/docs")
    print("=" * 60)
    print("Admin Key: admin_key_001")
    print("=" * 60)

# --- Main Execution --- #
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

