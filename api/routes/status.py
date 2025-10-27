"""
Status API Endpoints
Provide system status and monitoring information
"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from datetime import datetime
import psutil
import time

router = APIRouter()

# Global variable to track start time
start_time = time.time()

@router.get("/status")
async def get_status():
    """Get basic system status for frontend"""
    try:
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        # Simulate attack data (in real implementation, this would come from database)
        active_attacks = 0
        agents_registered = 5
        results_count = 12
        current_phase = "idle"

        return {
            "running": True,
            "agents_registered": agents_registered,
            "results_count": results_count,
            "current_phase": current_phase,
            "system": {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "disk_percent": disk.percent
            },
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")

@router.get("/api/status")
async def get_detailed_status():
    """Get detailed system status"""
    try:
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        # Check if we can connect to mock LLM service
        llm_status = {
            "available": True,
            "models": ["llama3:8b-instruct-fp16", "mixtral:latest", "llama3:latest"],
            "count": 3
        }

        # Mock active attacks count
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
                "connected": True,  # In real implementation, check actual database connection
                "active_attacks": active_attacks
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get detailed status: {str(e)}")

@router.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Basic health indicators
        system_healthy = True

        # Check system resources
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()

        if cpu_percent > 90 or memory.percent > 90:
            system_healthy = False

        return {
            "status": "healthy" if system_healthy else "degraded",
            "timestamp": datetime.now().isoformat(),
            "services": {
                "api": "operational",
                "database": "checking...",  # Would check actual database in real implementation
                "redis": "checking...",
                "ollama": "operational"
            },
            "ollama_models": [
                "llama3:8b-instruct-fp16",
                "mixtral:latest",
                "llama3:latest",
                "codellama:latest",
                "mistral:latest"
            ]
        }

    except Exception as e:
        raise HTTPException(status_code: f"Health check failed: {str(e)}")

@router.get("/uptime")
async def get_uptime():
    """Get system uptime"""
    try:
        current_time = time.time()
        uptime_seconds = int(current_time - start_time)

        hours = uptime_seconds // 3600
        minutes = (uptime_seconds % 3600) // 60
        seconds = uptime_seconds % 60

        return {
            "uptime": f"{hours}h {minutes}m {seconds}s",
            "uptime_seconds": uptime_seconds,
            "start_time": datetime.fromtimestamp(start_time).isoformat(),
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get uptime: {str(e)}")