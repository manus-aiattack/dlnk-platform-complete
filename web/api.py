"""
FastAPI application for dLNk dLNk Framework
Provides REST API for framework operations
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.orchestrator import Orchestrator
from core.logger import log
from core.data_models import Strategy
from config.settings import DEFAULT_WORKFLOW, WORKSPACE_DIR, API_DEBUG
import json
import os
from datetime import datetime

# Initialize FastAPI app
app = FastAPI(
    title="dLNk dLNk API",
    description="REST API for Autonomous Penetration Testing Framework",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global orchestrator instance
orchestrator: Optional[Orchestrator] = None


# Pydantic models
class TargetModel(BaseModel):
    """Target information model"""
    name: str
    url: str
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class WorkflowExecutionRequest(BaseModel):
    """Request model for workflow execution"""
    workflow_path: str = DEFAULT_WORKFLOW
    target: TargetModel


class AgentExecutionRequest(BaseModel):
    """Request model for agent execution"""
    agent_name: str
    directive: str
    context: Optional[Dict[str, Any]] = None


class StatusResponse(BaseModel):
    """Status response model"""
    running: bool
    current_phase: Optional[str]
    agents_registered: int
    results_count: int


# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize orchestrator on startup"""
    global orchestrator
    log.info("Starting dLNk dLNk API...")
    
    try:
        orchestrator = Orchestrator(workspace_dir=WORKSPACE_DIR)
        await orchestrator.initialize()
        log.success("API initialized successfully")
    except Exception as e:
        log.error(f"Failed to initialize API: {e}", exc_info=True)
        raise


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    if orchestrator:
        await orchestrator.cleanup()
        log.info("API shutdown complete")


# Dashboard endpoint
@app.get("/")
async def root():
    """Serve the dashboard HTML"""
    dashboard_path = Path(__file__).parent / "dashboard.html"
    if dashboard_path.exists():
        return FileResponse(dashboard_path)
    return {"message": "dLNk dLNk API - Visit /docs for API documentation"}


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "framework": "dLNk dLNk"
    }


# Status endpoint
@app.get("/status", response_model=StatusResponse)
async def get_status():
    """Get framework status"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    status = orchestrator.get_status()
    return StatusResponse(**status)


@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    log.info("WebSocket client connected for logs")
    
    if not orchestrator or not orchestrator.pubsub_manager:
        await websocket.send_json({"level": "error", "message": "Orchestrator or PubSubManager not initialized."})
        await websocket.close()
        return

    pubsub = orchestrator.pubsub_manager.redis.pubsub()
    await pubsub.subscribe("log_stream")

    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message["type"] == "message":
                log_entry = json.loads(message["data"])
                await websocket.send_json(log_entry)
            await asyncio.sleep(0.01)  # Prevent busy-waiting
    except WebSocketDisconnect:
        log.info("WebSocket client disconnected from logs")
    except Exception as e:
        log.error(f"WebSocket error: {e}", exc_info=True)
    finally:
        await pubsub.unsubscribe("log_stream")
        log.info("WebSocket unsubscribed from log_stream")


# Agents endpoints
@app.get("/agents")
async def list_agents():
    """List all available agents"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    agents = orchestrator.get_registered_agents()
    agent_info = []
    
    for agent_name in agents:
        info = orchestrator.get_agent_info(agent_name)
        if info:
            agent_info.append(info)
    
    return {
        "count": len(agent_info),
        "agents": agent_info
    }


@app.get("/agents/{agent_name}")
async def get_agent(agent_name: str):
    """Get information about a specific agent"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    info = orchestrator.get_agent_info(agent_name)
    if not info:
        raise HTTPException(status_code=404, detail=f"Agent {agent_name} not found")
    
    return info


# Workflow endpoints
@app.post("/workflows/execute")
async def execute_workflow(request: WorkflowExecutionRequest, background_tasks: BackgroundTasks):
    """Execute a workflow"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    try:
        target_dict = request.target.dict()
        
        # Run in background
        background_tasks.add_task(
            orchestrator.execute_workflow,
            request.workflow_path,
            target_dict
        )
        
        return {
            "status": "started",
            "message": f"Workflow execution started for target: {request.target.name}",
            "target": request.target.name
        }
    except Exception as e:
        log.error(f"Workflow execution failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# Agent execution endpoints
@app.post("/agents/execute")
async def execute_agent(request: AgentExecutionRequest):
    """Execute a single agent"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    try:
        strategy = Strategy(
            phase="api",
            directive=request.directive,
            context=request.context or {}
        )
        
        result = await orchestrator.execute_agent_directly(request.agent_name, strategy)
        
        return {
            "agent_name": request.agent_name,
            "success": result.success,
            "summary": result.summary,
            "errors": result.errors,
            "data": result.data
        }
    except Exception as e:
        log.error(f"Agent execution failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# Results endpoints
@app.get("/results")
async def get_results():
    """Get all campaign results"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    results = orchestrator.campaign_results
    
    return {
        "count": len(results),
        "results": [r.dict() if hasattr(r, 'dict') else str(r) for r in results]
    }


@app.get("/results/{index}")
async def get_result(index: int):
    """Get a specific result"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    if index < 0 or index >= len(orchestrator.campaign_results):
        raise HTTPException(status_code=404, detail="Result not found")
    
    result = orchestrator.campaign_results[index]
    return result.dict() if hasattr(result, 'dict') else str(result)


# ==================== LOOT MANAGEMENT ENDPOINTS ====================

@app.get("/loot/summary")
async def get_loot_summary():
    """รับสรุป Loot ทั้งหมด"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    loot_dir = Path(orchestrator.workspace_dir) / "loot"
    
    if not loot_dir.exists():
        return {
            "total_items": 0,
            "categories": {},
            "loot_dir": str(loot_dir)
        }
    
    # Count loot by category
    categories = {
        "database_dumps": 0,
        "credentials": 0,
        "session_tokens": 0,
        "files": 0,
        "webshells": 0,
        "c2_agents": 0
    }
    
    total_size = 0
    
    for category in categories.keys():
        cat_dir = loot_dir / category
        if cat_dir.exists():
            files = list(cat_dir.glob("*"))
            categories[category] = len(files)
            total_size += sum(f.stat().st_size for f in files if f.is_file())
    
    return {
        "total_items": sum(categories.values()),
        "categories": categories,
        "total_size_bytes": total_size,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
        "loot_dir": str(loot_dir)
    }


@app.get("/loot/{category}")
async def get_loot_by_category(category: str):
    """รับ Loot ตามหมวดหมู่"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    valid_categories = ["database_dumps", "credentials", "session_tokens", "files", "webshells", "c2_agents"]
    
    if category not in valid_categories:
        raise HTTPException(status_code=400, detail=f"Invalid category. Must be one of: {', '.join(valid_categories)}")
    
    loot_dir = Path(orchestrator.workspace_dir) / "loot" / category
    
    if not loot_dir.exists():
        return {
            "category": category,
            "items": [],
            "count": 0
        }
    
    items = []
    for file_path in loot_dir.glob("*"):
        if file_path.is_file():
            stat = file_path.stat()
            items.append({
                "filename": file_path.name,
                "size_bytes": stat.st_size,
                "size_kb": round(stat.st_size / 1024, 2),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "download_url": f"/loot/download/{category}/{file_path.name}"
            })
    
    # Sort by modified time (newest first)
    items.sort(key=lambda x: x["modified"], reverse=True)
    
    return {
        "category": category,
        "items": items,
        "count": len(items)
    }


@app.get("/loot/download/{category}/{filename}")
async def download_loot(category: str, filename: str):
    """ดาวน์โหลด Loot ไฟล์"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    # Security: Prevent path traversal
    if ".." in filename or ".." in category or "/" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    loot_file = Path(orchestrator.workspace_dir) / "loot" / category / filename
    
    if not loot_file.exists() or not loot_file.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        path=str(loot_file),
        filename=filename,
        media_type="application/octet-stream"
    )


@app.get("/loot/reports")
async def get_loot_reports():
    """รับ Loot Reports ทั้งหมด"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    reports_dir = Path(orchestrator.workspace_dir) / "loot"
    
    if not reports_dir.exists():
        return {
            "reports": [],
            "count": 0
        }
    
    reports = []
    for report_file in reports_dir.glob("loot_report_*.json"):
        if report_file.is_file():
            try:
                with open(report_file, 'r') as f:
                    report_data = json.load(f)
                
                stat = report_file.stat()
                reports.append({
                    "filename": report_file.name,
                    "attack_id": report_data.get("attack_id", "unknown"),
                    "target": report_data.get("target", "unknown"),
                    "loot_count": len(report_data.get("loot", [])),
                    "timestamp": report_data.get("timestamp", ""),
                    "size_kb": round(stat.st_size / 1024, 2),
                    "download_url": f"/loot/download/reports/{report_file.name}"
                })
            except Exception as e:
                log.error(f"Failed to read report {report_file}: {e}")
    
    # Sort by timestamp (newest first)
    reports.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return {
        "reports": reports,
        "count": len(reports)
    }


@app.delete("/loot/{category}/{filename}")
async def delete_loot(category: str, filename: str):
    """ลบ Loot ไฟล์"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    # Security: Prevent path traversal
    if ".." in filename or ".." in category or "/" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    loot_file = Path(orchestrator.workspace_dir) / "loot" / category / filename
    
    if not loot_file.exists() or not loot_file.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    
    try:
        loot_file.unlink()
        log.info(f"Deleted loot file: {loot_file}")
        return {"success": True, "message": f"Deleted {filename}"}
    except Exception as e:
        log.error(f"Failed to delete {loot_file}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete file: {str(e)}")


@app.post("/auto-exploit")
async def auto_exploit(target_url: str, background_tasks: BackgroundTasks):
    """โจมตีอัตโนมัติ"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    # Safety check
    if not orchestrator.is_target_safe(target_url):
        raise HTTPException(status_code=400, detail="Target is blocked for safety reasons (localhost/127.0.0.1)")
    
    # Run auto exploit in background
    async def run_auto_exploit():
        try:
            result = await orchestrator.auto_exploit_target(target_url)
            log.success(f"Auto exploit completed for {target_url}")
            return result
        except Exception as e:
            log.error(f"Auto exploit failed: {e}")
            return {"success": False, "error": str(e)}
    
    background_tasks.add_task(run_auto_exploit)
    
    return {
        "success": True,
        "message": f"Auto exploit started for {target_url}",
        "target": target_url
    }


# Error handlers
@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions"""
    log.error(f"Unhandled exception: {exc}", exc_info=True)
    return {
        "error": "Internal server error",
        "detail": str(exc)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=API_DEBUG)

