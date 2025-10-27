"""
Agents Manager API - Manage all attack agents in the system
"""
import os
import importlib.util
from pathlib import Path
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/agents", tags=["agents"])


class AgentInfo(BaseModel):
    """Agent information model"""
    name: str
    category: str
    path: str
    description: str = ""
    enabled: bool = True


class AgentExecuteRequest(BaseModel):
    """Agent execution request"""
    agent_name: str
    target: str
    options: Dict[str, Any] = {}


def scan_agents() -> List[AgentInfo]:
    """Scan and return all available agents"""
    agents = []
    agents_dir = Path("/home/ubuntu/aiprojectattack/agents")
    
    if not agents_dir.exists():
        return agents
    
    # Scan all categories
    for category_dir in agents_dir.iterdir():
        if not category_dir.is_dir() or category_dir.name.startswith('_'):
            continue
        
        category_name = category_dir.name.replace('_', ' ').title()
        
        # Scan all agents in category
        for agent_file in category_dir.glob("*_agent.py"):
            agent_name = agent_file.stem.replace('_agent', '').replace('_', ' ').title()
            
            agents.append(AgentInfo(
                name=agent_name,
                category=category_name,
                path=str(agent_file),
                description=f"{agent_name} agent for {category_name}",
                enabled=True
            ))
    
    # Also scan root agents directory
    for agent_file in agents_dir.glob("*_agent.py"):
        agent_name = agent_file.stem.replace('_agent', '').replace('_', ' ').title()
        
        agents.append(AgentInfo(
            name=agent_name,
            category="General",
            path=str(agent_file),
            description=f"{agent_name} agent",
            enabled=True
        ))
    
    return sorted(agents, key=lambda x: (x.category, x.name))


def scan_core_modules() -> List[Dict[str, Any]]:
    """Scan and return all core modules"""
    modules = []
    core_dir = Path("/home/ubuntu/aiprojectattack/core")
    
    if not core_dir.exists():
        return modules
    
    for module_file in core_dir.glob("*.py"):
        if module_file.name.startswith('_'):
            continue
        
        module_name = module_file.stem.replace('_', ' ').title()
        
        modules.append({
            "name": module_name,
            "path": str(module_file),
            "size": module_file.stat().st_size,
            "type": "core"
        })
    
    return sorted(modules, key=lambda x: x['name'])


@router.get("/list")
async def list_agents():
    """List all available agents"""
    try:
        agents = scan_agents()
        
        # Group by category
        categories = {}
        for agent in agents:
            if agent.category not in categories:
                categories[agent.category] = []
            categories[agent.category].append({
                "name": agent.name,
                "description": agent.description,
                "enabled": agent.enabled
            })
        
        return {
            "status": "success",
            "total_agents": len(agents),
            "total_categories": len(categories),
            "categories": categories
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_agent_stats():
    """Get agent statistics"""
    try:
        agents = scan_agents()
        core_modules = scan_core_modules()
        
        # Count by category
        category_counts = {}
        for agent in agents:
            category_counts[agent.category] = category_counts.get(agent.category, 0) + 1
        
        return {
            "status": "success",
            "total_agents": len(agents),
            "total_core_modules": len(core_modules),
            "categories": category_counts,
            "agents_by_category": {
                cat: [a.name for a in agents if a.category == cat]
                for cat in category_counts.keys()
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/categories")
async def list_categories():
    """List all agent categories"""
    try:
        agents = scan_agents()
        
        categories = {}
        for agent in agents:
            if agent.category not in categories:
                categories[agent.category] = {
                    "name": agent.category,
                    "count": 0,
                    "agents": []
                }
            categories[agent.category]["count"] += 1
            categories[agent.category]["agents"].append(agent.name)
        
        return {
            "status": "success",
            "categories": list(categories.values())
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/core")
async def list_core_modules():
    """List all core modules"""
    try:
        modules = scan_core_modules()
        
        return {
            "status": "success",
            "total_modules": len(modules),
            "modules": modules
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute")
async def execute_agent(request: AgentExecuteRequest):
    """Execute an agent (placeholder for now)"""
    return {
        "status": "queued",
        "agent": request.agent_name,
        "target": request.target,
        "message": "Agent execution queued - full implementation coming soon"
    }


@router.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        agents = scan_agents()
        core_modules = scan_core_modules()
        
        return {
            "status": "healthy",
            "agents_available": len(agents),
            "core_modules_available": len(core_modules),
            "system": "operational"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }

