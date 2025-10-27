"""
API Routes สำหรับ Distributed Fuzzing System
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime

from services.distributed_fuzzing import DistributedFuzzingOrchestrator
from core.logger import log


router = APIRouter(prefix="/fuzzing", tags=["fuzzing"])

# Global orchestrator instance
orchestrator = None


class NodeRegistration(BaseModel):
    """Node registration request"""
    hostname: str
    ip_address: str
    port: int
    cpu_cores: int
    memory_gb: int


class JobSubmission(BaseModel):
    """Job submission request"""
    target_binary: str
    input_seeds: List[str]
    duration: int = 3600
    timeout: int = 100
    memory_limit: int = 256


class HeartbeatUpdate(BaseModel):
    """Heartbeat update from node"""
    node_id: str
    metrics: Dict[str, Any]


@router.on_event("startup")
async def startup_event():
    """Initialize orchestrator on startup"""
    global orchestrator
    orchestrator = DistributedFuzzingOrchestrator()
    await orchestrator.start()
    log.info("[FuzzingAPI] Distributed fuzzing orchestrator started")


@router.on_event("shutdown")
async def shutdown_event():
    """Shutdown orchestrator"""
    if orchestrator:
        await orchestrator.stop()
    log.info("[FuzzingAPI] Distributed fuzzing orchestrator stopped")


@router.post("/nodes/register")
async def register_node(registration: NodeRegistration) -> Dict[str, Any]:
    """
    ลงทะเบียน fuzzing node
    
    Args:
        registration: Node registration data
    
    Returns:
        Node ID and registration status
    """
    try:
        node_id = await orchestrator.register_node(
            hostname=registration.hostname,
            ip_address=registration.ip_address,
            port=registration.port,
            cpu_cores=registration.cpu_cores,
            memory_gb=registration.memory_gb
        )
        
        return {
            "success": True,
            "node_id": node_id,
            "message": "Node registered successfully"
        }
    
    except Exception as e:
        log.error(f"[FuzzingAPI] Failed to register node: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/nodes/{node_id}")
async def unregister_node(node_id: str) -> Dict[str, Any]:
    """
    ยกเลิกการลงทะเบียน node
    
    Args:
        node_id: Node ID
    
    Returns:
        Unregistration status
    """
    try:
        success = await orchestrator.unregister_node(node_id)
        
        if success:
            return {
                "success": True,
                "message": "Node unregistered successfully"
            }
        else:
            raise HTTPException(status_code=404, detail="Node not found")
    
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"[FuzzingAPI] Failed to unregister node: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nodes")
async def get_nodes() -> Dict[str, Any]:
    """
    รับรายการ nodes ทั้งหมด
    
    Returns:
        List of nodes
    """
    try:
        nodes = orchestrator.get_nodes()
        
        return {
            "success": True,
            "nodes": nodes,
            "total": len(nodes)
        }
    
    except Exception as e:
        log.error(f"[FuzzingAPI] Failed to get nodes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nodes/{node_id}")
async def get_node(node_id: str) -> Dict[str, Any]:
    """
    รับข้อมูล node
    
    Args:
        node_id: Node ID
    
    Returns:
        Node information
    """
    try:
        nodes = orchestrator.get_nodes()
        node = next((n for n in nodes if n["node_id"] == node_id), None)
        
        if node:
            return {
                "success": True,
                "node": node
            }
        else:
            raise HTTPException(status_code=404, detail="Node not found")
    
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"[FuzzingAPI] Failed to get node: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/jobs/submit")
async def submit_job(submission: JobSubmission) -> Dict[str, Any]:
    """
    Submit fuzzing job
    
    Args:
        submission: Job submission data
    
    Returns:
        Job ID and submission status
    """
    try:
        job_id = await orchestrator.submit_job(
            target_binary=submission.target_binary,
            input_seeds=submission.input_seeds,
            duration=submission.duration,
            timeout=submission.timeout,
            memory_limit=submission.memory_limit
        )
        
        return {
            "success": True,
            "job_id": job_id,
            "message": "Job submitted successfully"
        }
    
    except Exception as e:
        log.error(f"[FuzzingAPI] Failed to submit job: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/jobs")
async def get_jobs() -> Dict[str, Any]:
    """
    รับรายการ jobs ทั้งหมด
    
    Returns:
        List of jobs
    """
    try:
        jobs = orchestrator.get_jobs()
        
        return {
            "success": True,
            "jobs": jobs,
            "total": len(jobs)
        }
    
    except Exception as e:
        log.error(f"[FuzzingAPI] Failed to get jobs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/jobs/{job_id}")
async def get_job(job_id: str) -> Dict[str, Any]:
    """
    รับข้อมูล job
    
    Args:
        job_id: Job ID
    
    Returns:
        Job information
    """
    try:
        jobs = orchestrator.get_jobs()
        job = next((j for j in jobs if j["job_id"] == job_id), None)
        
        if job:
            return {
                "success": True,
                "job": job
            }
        else:
            raise HTTPException(status_code=404, detail="Job not found")
    
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"[FuzzingAPI] Failed to get job: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/heartbeat")
async def update_heartbeat(heartbeat: HeartbeatUpdate) -> Dict[str, Any]:
    """
    อัพเดท heartbeat จาก node
    
    Args:
        heartbeat: Heartbeat data
    
    Returns:
        Update status
    """
    try:
        success = await orchestrator.update_heartbeat(
            node_id=heartbeat.node_id,
            metrics=heartbeat.metrics
        )
        
        if success:
            return {
                "success": True,
                "message": "Heartbeat updated"
            }
        else:
            raise HTTPException(status_code=404, detail="Node not found")
    
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"[FuzzingAPI] Failed to update heartbeat: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/crashes")
async def get_crashes() -> Dict[str, Any]:
    """
    รับรายการ crashes ทั้งหมด
    
    Returns:
        List of crashes
    """
    try:
        crashes = orchestrator.get_crashes()
        
        return {
            "success": True,
            "crashes": crashes,
            "total": len(crashes)
        }
    
    except Exception as e:
        log.error(f"[FuzzingAPI] Failed to get crashes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_status() -> Dict[str, Any]:
    """
    รับสถานะของระบบ fuzzing
    
    Returns:
        System status
    """
    try:
        status = orchestrator.get_status()
        
        return {
            "success": True,
            "status": status,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        log.error(f"[FuzzingAPI] Failed to get status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

