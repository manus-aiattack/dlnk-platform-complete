"""
Agent Manager Service
Manages dynamic agent execution as Kubernetes pods
"""

import asyncio
import os
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from core.logger import log
from core.context_manager import ContextManager


class AgentExecutionRequest(BaseModel):
    agent_name: str
    directive: str
    context: Dict[str, Any]
    timeout: int = 3600
    resources: Optional[Dict[str, str]] = None


class AgentStatus(BaseModel):
    agent_id: str
    agent_name: str
    status: str
    started_at: Optional[str]
    completed_at: Optional[str]
    result: Optional[Dict[str, Any]]
    logs: Optional[str]


class AgentManagerService:
    """Manages agent execution in Kubernetes"""
    
    def __init__(self, namespace: str = "dlnk-dlnk"):
        self.namespace = namespace
        self.k8s_core_api = None
        self.context_manager = None
        self.active_agents: Dict[str, AgentStatus] = {}
        self.max_concurrent_agents = int(os.getenv("MAX_CONCURRENT_AGENTS", "100"))
        
    async def initialize(self):
        """Initialize Kubernetes client and context manager"""
        try:
            # Load Kubernetes config
            try:
                config.load_incluster_config()
                log.info("Loaded in-cluster Kubernetes config")
            except Exception as e:
                config.load_kube_config()
                log.info("Loaded local Kubernetes config")
            
            self.k8s_core_api = client.CoreV1Api()
            
            # Initialize context manager
            self.context_manager = ContextManager()
            await self.context_manager.setup()
            
            log.success("Agent Manager Service initialized")
            
        except Exception as e:
            log.error(f"Failed to initialize Agent Manager: {e}")
            raise
    
    async def launch_agent(self, request: AgentExecutionRequest) -> str:
        """Launch an agent as a Kubernetes pod"""
        try:
            # Check concurrent agent limit
            active_count = len([a for a in self.active_agents.values() if a.status == "running"])
            if active_count >= self.max_concurrent_agents:
                raise Exception(f"Maximum concurrent agents ({self.max_concurrent_agents}) reached")
            
            # Generate unique agent ID
            agent_id = f"agent-{request.agent_name.lower()}-{uuid.uuid4().hex[:8]}"
            
            # Create pod specification
            pod_spec = self._create_agent_pod_spec(agent_id, request)
            
            # Launch pod
            self.k8s_core_api.create_namespaced_pod(
                namespace=self.namespace,
                body=pod_spec
            )
            
            # Track agent status
            self.active_agents[agent_id] = AgentStatus(
                agent_id=agent_id,
                agent_name=request.agent_name,
                status="running",
                started_at=datetime.now().isoformat(),
                completed_at=None,
                result=None,
                logs=None
            )
            
            # Store agent context in Redis
            await self.context_manager.set_context(
                f"agent:{agent_id}:request",
                {
                    "agent_name": request.agent_name,
                    "directive": request.directive,
                    "context": request.context,
                    "timeout": request.timeout
                }
            )
            
            log.info(f"Launched agent: {agent_id} ({request.agent_name})")
            return agent_id
            
        except Exception as e:
            log.error(f"Failed to launch agent: {e}")
            raise
    
    def _create_agent_pod_spec(self, agent_id: str, request: AgentExecutionRequest) -> Dict[str, Any]:
        """Create Kubernetes pod specification for agent"""
        
        # Default resources
        resources = request.resources or {
            "requests": {"memory": "512Mi", "cpu": "250m"},
            "limits": {"memory": "1Gi", "cpu": "500m"}
        }
        
        pod_spec = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": agent_id,
                "namespace": self.namespace,
                "labels": {
                    "app": "dlnk-agent",
                    "agent-name": request.agent_name.lower(),
                    "agent-id": agent_id
                }
            },
            "spec": {
                "restartPolicy": "Never",
                "containers": [{
                    "name": "agent",
                    "image": f"{os.getenv('AGENT_IMAGE_REGISTRY', 'dlnk-dlnk')}/agent-{request.agent_name.lower()}:latest",
                    "imagePullPolicy": "Always",
                    "env": [
                        {"name": "AGENT_ID", "value": agent_id},
                        {"name": "AGENT_NAME", "value": request.agent_name},
                        {"name": "DIRECTIVE", "value": request.directive},
                        {"name": "CONTEXT_JSON", "value": str(request.context)},
                        {"name": "REDIS_HOST", "value": os.getenv("REDIS_HOST", "redis-cluster")},
                        {"name": "REDIS_PORT", "value": os.getenv("REDIS_PORT", "6379")},
                        {"name": "TIMEOUT", "value": str(request.timeout)}
                    ],
                    "resources": resources
                }],
                "activeDeadlineSeconds": request.timeout
            }
        }
        
        return pod_spec
    
    async def get_agent_status(self, agent_id: str) -> AgentStatus:
        """Get status of an agent"""
        try:
            if agent_id not in self.active_agents:
                raise Exception(f"Agent {agent_id} not found")
            
            # Query Kubernetes for pod status
            try:
                pod = self.k8s_core_api.read_namespaced_pod(
                    name=agent_id,
                    namespace=self.namespace
                )
                
                # Update status based on pod phase
                if pod.status.phase == "Running":
                    self.active_agents[agent_id].status = "running"
                elif pod.status.phase == "Succeeded":
                    self.active_agents[agent_id].status = "completed"
                    self.active_agents[agent_id].completed_at = datetime.now().isoformat()
                    
                    # Retrieve result from context
                    result = await self.context_manager.get_context(f"agent:{agent_id}:result")
                    self.active_agents[agent_id].result = result
                    
                elif pod.status.phase == "Failed":
                    self.active_agents[agent_id].status = "failed"
                    self.active_agents[agent_id].completed_at = datetime.now().isoformat()
                    
            except ApiException as e:
                if e.status == 404:
                    self.active_agents[agent_id].status = "not_found"
            
            return self.active_agents[agent_id]
            
        except Exception as e:
            log.error(f"Failed to get agent status: {e}")
            raise
    
    async def get_agent_logs(self, agent_id: str) -> str:
        """Get logs from an agent pod"""
        try:
            logs = self.k8s_core_api.read_namespaced_pod_log(
                name=agent_id,
                namespace=self.namespace
            )
            return logs
            
        except ApiException as e:
            if e.status == 404:
                return "Agent pod not found"
            raise
    
    async def terminate_agent(self, agent_id: str):
        """Terminate a running agent"""
        try:
            self.k8s_core_api.delete_namespaced_pod(
                name=agent_id,
                namespace=self.namespace
            )
            
            if agent_id in self.active_agents:
                self.active_agents[agent_id].status = "terminated"
                self.active_agents[agent_id].completed_at = datetime.now().isoformat()
            
            log.info(f"Terminated agent: {agent_id}")
            
        except ApiException as e:
            if e.status == 404:
                log.warning(f"Agent {agent_id} not found for termination")
            else:
                raise
    
    async def list_active_agents(self) -> List[AgentStatus]:
        """List all active agents"""
        return list(self.active_agents.values())
    
    async def cleanup_completed_agents(self, max_age_hours: int = 24):
        """Cleanup completed agent pods"""
        try:
            pods = self.k8s_core_api.list_namespaced_pod(
                namespace=self.namespace,
                label_selector="app=dlnk-agent"
            )
            
            cleaned = 0
            for pod in pods.items:
                if pod.status.phase in ["Succeeded", "Failed"]:
                    # Check age
                    if pod.status.start_time:
                        age = datetime.now(pod.status.start_time.tzinfo) - pod.status.start_time
                        if age.total_seconds() > max_age_hours * 3600:
                            self.k8s_core_api.delete_namespaced_pod(
                                name=pod.metadata.name,
                                namespace=self.namespace
                            )
                            cleaned += 1
            
            log.info(f"Cleaned up {cleaned} completed agent pods")
            
        except Exception as e:
            log.error(f"Failed to cleanup agents: {e}")


# FastAPI Application
app = FastAPI(title="Agent Manager Service")
agent_manager: Optional[AgentManagerService] = None


@app.on_event("startup")
async def startup_event():
    """Initialize service on startup"""
    global agent_manager
    
    try:
        namespace = os.getenv("KUBERNETES_NAMESPACE", "dlnk-dlnk")
        agent_manager = AgentManagerService(namespace)
        await agent_manager.initialize()
        
        # Start background cleanup task
        asyncio.create_task(periodic_cleanup())
        
        log.success("Agent Manager Service started")
        
    except Exception as e:
        log.error(f"Failed to start Agent Manager Service: {e}")
        raise


async def periodic_cleanup():
    """Periodic cleanup of completed agents"""
    while True:
        try:
            await asyncio.sleep(3600)  # Every hour
            await agent_manager.cleanup_completed_agents()
        except Exception as e:
            log.error(f"Cleanup task error: {e}")


@app.post("/agents/launch")
async def launch_agent(request: AgentExecutionRequest):
    """Launch a new agent"""
    try:
        agent_id = await agent_manager.launch_agent(request)
        return {"agent_id": agent_id, "status": "launched"}
    except Exception as e:
        log.error(f"Failed to launch agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/agents/{agent_id}/status")
async def get_agent_status(agent_id: str):
    """Get agent status"""
    try:
        status = await agent_manager.get_agent_status(agent_id)
        return status.dict()
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/agents/{agent_id}/logs")
async def get_agent_logs(agent_id: str):
    """Get agent logs"""
    try:
        logs = await agent_manager.get_agent_logs(agent_id)
        return {"agent_id": agent_id, "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/agents/{agent_id}")
async def terminate_agent(agent_id: str):
    """Terminate an agent"""
    try:
        await agent_manager.terminate_agent(agent_id)
        return {"agent_id": agent_id, "status": "terminated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/agents")
async def list_agents():
    """List all active agents"""
    try:
        agents = await agent_manager.list_active_agents()
        return {"agents": [a.dict() for a in agents]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint"""
    if agent_manager is None:
        raise HTTPException(status_code=503, detail="Service not ready")
    return {"status": "ready"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)

