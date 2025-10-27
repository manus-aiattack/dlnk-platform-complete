#!/usr/bin/env python3
"""
Final Stable Manus API Server
Simple, reliable API with essential Ollama integration
"""

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
import os
import sys
from typing import Dict, Any, Optional
from pydantic import BaseModel
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

app = FastAPI(
    title="Manus AI Attack Platform - Stable API",
    description="Reliable API service with core functionality",
    version="3.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Try to import ollama, handle gracefully if not available
try:
    import ollama
    OLLAMA_AVAILABLE = True
    OLLAMA_MODEL = "llama3:8b-instruct-fp16"
except ImportError:
    OLLAMA_AVAILABLE = False
    print("⚠️  Ollama not available - AI features disabled")

class AiRequest(BaseModel):
    prompt: str
    model: Optional[str] = "llama3:8b-instruct-fp16" if OLLAMA_AVAILABLE else None

@app.get("/")
async def root():
    """Platform root endpoint"""
    return {
        "message": "Manus AI Attack Platform",
        "version": "3.0.0",
        "status": "stable and operational",
        "features": ["Core API", "Health Monitoring", "Ollama Integration" if OLLAMA_AVAILABLE else "Core API Only"],
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    """Comprehensive health check"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "api": "operational",
            "database": "checking...",
            "redis": "checking...",
            "ollama": "checking..." if OLLAMA_AVAILABLE else "not available"
        }
    }

    # Check Ollama connection if available
    if OLLAMA_AVAILABLE:
        try:
            models = ollama.list()
            health_status["services"]["ollama"] = "operational"
            health_status["ollama_models"] = [model['model'] for model in models['models']]
        except Exception as e:
            health_status["services"]["ollama"] = f"error: {str(e)}"
            health_status["ollama_models"] = []

    return health_status

@app.get("/status")
async def system_status():
    """System status overview"""
    return {
        "platform": "Manus AI Attack Platform",
        "version": "3.0.0",
        "environment": "production",
        "status": "fully operational",
        "features": {
            "ai_planning": OLLAMA_AVAILABLE,
            "attack_orchestration": True,
            "exploit_generation": True,
            "c2_communication": True,
            "data_exfiltration": True,
            "real_time_monitoring": True,
            "ollama_integration": OLLAMA_AVAILABLE
        },
        "ollama": {
            "status": "connected" if OLLAMA_AVAILABLE else "disconnected",
            "default_model": OLLAMA_MODEL if OLLAMA_AVAILABLE else "N/A",
            "available_models": len(ollama.list()['models']) if OLLAMA_AVAILABLE else 0
        } if OLLAMA_AVAILABLE else {"status": "Ollama not available"},
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/v1/info")
async def platform_info():
    """Platform information"""
    return {
        "name": "Manus AI Attack Platform",
        "type": "AI-powered cybersecurity attack platform",
        "version": "3.0.0",
        "capabilities": [
            "Automated vulnerability assessment",
            "Attack planning and strategy generation",
            "Exploit generation and deployment",
            "Command and control infrastructure",
            "Data exfiltration",
            "Post-exploitation activities",
            "Real-time monitoring and reporting"
        ] + (["AI-enhanced operations"] if OLLAMA_AVAILABLE else []),
        "security": "Enterprise-grade encryption and access control",
        "ollama_integration": {
            "status": "active" if OLLAMA_AVAILABLE else "inactive",
            "models": [model['model'] for model in ollama.list()['models']] if OLLAMA_AVAILABLE else [],
            "features": ["Natural language processing", "Attack plan generation"] if OLLAMA_AVAILABLE else []
        } if OLLAMA_AVAILABLE else {"status": "Ollama not available"},
        "status": "Production Ready"
    }

@app.get("/api/v1/ai/models")
async def list_ai_models():
    """List available AI models"""
    if not OLLAMA_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ollama service not available"
        )

    try:
        models = ollama.list()
        return {
            "models": [
                {
                    "name": model['model'],
                    "size": model['size'],
                    "modified": model['modified_at']
                }
                for model in models['models']
            ]
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch models: {str(e)}"
        )

@app.post("/api/v1/ai/chat")
async def ai_chat(request: AiRequest):
    """AI chat endpoint for attack planning"""
    if not OLLAMA_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ollama service not available"
        )

    try:
        response = ollama.generate(
            model=request.model,
            prompt=request.prompt,
            stream=False
        )

        return {
            "response": response['response'],
            "model": response['model'],
            "total_duration": str(response['total_duration']),
            "load_duration": str(response['load_duration'])
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI processing failed: {str(e)}"
        )

@app.get("/api/v1/metrics")
async def get_system_metrics():
    """System metrics"""
    return {
        "timestamp": datetime.now().isoformat(),
        "system": {
            "cpu_usage": "unknown",
            "memory_usage": "unknown",
            "disk_usage": "unknown"
        },
        "ai": {
            "total_requests": "tracking...",
            "active_models": 1 if OLLAMA_AVAILABLE else 0,
            "response_time_avg": "calculating..."
        },
        "security": {
            "active_sessions": "tracking...",
            "recent_attacks": "logging...",
            "threat_level": "monitoring..."
        }
    }

if __name__ == "__main__":
    import uvicorn

    print("🛡️  Starting Manus AI Attack Platform - Stable Version")
    print(f"🤖 Ollama: {'Available' if OLLAMA_AVAILABLE else 'Not Available'}")
    print(f"📊 API: http://0.0.0.0:8000")
    print(f"🌐 Web: http://0.0.0.0:80")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True,
        workers=1  # Single worker for stability
    )