"""
Scan API Routes
Provides scanning capabilities via Nmap and other tools
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
import asyncio
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan", tags=["scan"])


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"  # quick, full, vuln, stealth
    ports: Optional[str] = None
    options: Optional[dict] = None


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    results: Optional[dict] = None


# Store active scans
active_scans = {}


@router.post("/quick", response_model=ScanResponse)
async def quick_scan(request: ScanRequest):
    """
    Perform quick scan on target
    
    Args:
        request: ScanRequest with target and options
    
    Returns:
        ScanResponse with scan results
    """
    try:
        # Import agent
        from agents.nmap_agent import NmapAgent
        
        agent = NmapAgent()
        
        # Perform quick scan
        result = await agent.run("quick_scan", {"target": request.target})
        
        if result.success:
            return ScanResponse(
                scan_id=f"scan_{request.target}",
                status="completed",
                target=request.target,
                results=result.to_dict()
            )
        else:
            raise HTTPException(status_code=500, detail=str(result.errors))
    
    except Exception as e:
        logger.error(f"Quick scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/full", response_model=ScanResponse)
async def full_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Perform full scan on target (background task)
    
    Args:
        request: ScanRequest with target and options
        background_tasks: FastAPI background tasks
    
    Returns:
        ScanResponse with scan ID
    """
    try:
        import uuid
        scan_id = str(uuid.uuid4())
        
        # Store scan status
        active_scans[scan_id] = {
            "status": "running",
            "target": request.target,
            "results": None
        }
        
        # Run scan in background
        async def run_full_scan():
            try:
                from agents.nmap_agent import NmapAgent
                
                agent = NmapAgent()
                result = await agent.run("full_scan", {"target": request.target})
                
                active_scans[scan_id]["status"] = "completed"
                active_scans[scan_id]["results"] = result.to_dict()
            except Exception as e:
                active_scans[scan_id]["status"] = "failed"
                active_scans[scan_id]["error"] = str(e)
        
        background_tasks.add_task(run_full_scan)
        
        return ScanResponse(
            scan_id=scan_id,
            status="running",
            target=request.target
        )
    
    except Exception as e:
        logger.error(f"Full scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/vuln", response_model=ScanResponse)
async def vulnerability_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Perform vulnerability scan on target
    
    Args:
        request: ScanRequest with target and options
        background_tasks: FastAPI background tasks
    
    Returns:
        ScanResponse with scan ID
    """
    try:
        import uuid
        scan_id = str(uuid.uuid4())
        
        active_scans[scan_id] = {
            "status": "running",
            "target": request.target,
            "results": None
        }
        
        async def run_vuln_scan():
            try:
                from agents.nmap_agent import NmapAgent
                
                agent = NmapAgent()
                result = await agent.run("vuln_scan", {"target": request.target})
                
                active_scans[scan_id]["status"] = "completed"
                active_scans[scan_id]["results"] = result.to_dict()
            except Exception as e:
                active_scans[scan_id]["status"] = "failed"
                active_scans[scan_id]["error"] = str(e)
        
        background_tasks.add_task(run_vuln_scan)
        
        return ScanResponse(
            scan_id=scan_id,
            status="running",
            target=request.target
        )
    
    except Exception as e:
        logger.error(f"Vulnerability scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/{scan_id}", response_model=ScanResponse)
async def get_scan_status(scan_id: str):
    """
    Get scan status and results
    
    Args:
        scan_id: Scan ID from previous scan request
    
    Returns:
        ScanResponse with current status and results
    """
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = active_scans[scan_id]
    
    return ScanResponse(
        scan_id=scan_id,
        status=scan["status"],
        target=scan["target"],
        results=scan.get("results")
    )


@router.get("/list")
async def list_scans():
    """
    List all active and completed scans
    
    Returns:
        List of scans with their status
    """
    return {
        "scans": [
            {
                "scan_id": scan_id,
                "target": scan["target"],
                "status": scan["status"]
            }
            for scan_id, scan in active_scans.items()
        ]
    }


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str):
    """
    Delete scan results
    
    Args:
        scan_id: Scan ID to delete
    
    Returns:
        Success message
    """
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    del active_scans[scan_id]
    
    return {"message": "Scan deleted successfully"}


@router.post("/port-scan")
async def port_scan(request: ScanRequest):
    """
    Perform port scan on specific ports
    
    Args:
        request: ScanRequest with target and ports
    
    Returns:
        ScanResponse with port scan results
    """
    try:
        from agents.nmap_agent import NmapAgent
        
        agent = NmapAgent()
        
        result = await agent.run("port_scan", {
            "target": request.target,
            "ports": request.ports or "1-1000"
        })
        
        if result.success:
            return ScanResponse(
                scan_id=f"portscan_{request.target}",
                status="completed",
                target=request.target,
                results=result.to_dict()
            )
        else:
            raise HTTPException(status_code=500, detail=str(result.errors))
    
    except Exception as e:
        logger.error(f"Port scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/service-detection")
async def service_detection(request: ScanRequest):
    """
    Perform service detection on target
    
    Args:
        request: ScanRequest with target
    
    Returns:
        ScanResponse with service detection results
    """
    try:
        from agents.nmap_agent import NmapAgent
        
        agent = NmapAgent()
        
        result = await agent.run("service_detection", {"target": request.target})
        
        if result.success:
            return ScanResponse(
                scan_id=f"service_{request.target}",
                status="completed",
                target=request.target,
                results=result.to_dict()
            )
        else:
            raise HTTPException(status_code=500, detail=str(result.errors))
    
    except Exception as e:
        logger.error(f"Service detection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

