"""
WebSocket Handler
Real-time communication for logs, attacks, and agent status
"""

from fastapi import WebSocket, WebSocketDisconnect
from typing import List, Dict
import asyncio
import json
import logging

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manage WebSocket connections"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.log_connections: List[WebSocket] = []
        self.attack_connections: List[WebSocket] = []
        self.agent_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket, connection_type: str = "general"):
        """Connect new WebSocket client"""
        await websocket.accept()
        self.active_connections.append(websocket)
        
        if connection_type == "logs":
            self.log_connections.append(websocket)
        elif connection_type == "attacks":
            self.attack_connections.append(websocket)
        elif connection_type == "agents":
            self.agent_connections.append(websocket)
        
        logger.info(f"WebSocket connected: {connection_type}")
    
    def disconnect(self, websocket: WebSocket):
        """Disconnect WebSocket client"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.log_connections:
            self.log_connections.remove(websocket)
        if websocket in self.attack_connections:
            self.attack_connections.remove(websocket)
        if websocket in self.agent_connections:
            self.agent_connections.remove(websocket)
        
        logger.info("WebSocket disconnected")
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send message to specific client"""
        await websocket.send_text(message)
    
    async def broadcast(self, message: str, connection_type: str = "all"):
        """Broadcast message to all clients of specific type"""
        connections = self.active_connections
        
        if connection_type == "logs":
            connections = self.log_connections
        elif connection_type == "attacks":
            connections = self.attack_connections
        elif connection_type == "agents":
            connections = self.agent_connections
        
        for connection in connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Broadcast error: {e}")
    
    async def broadcast_json(self, data: Dict, connection_type: str = "all"):
        """Broadcast JSON data to all clients"""
        message = json.dumps(data)
        await self.broadcast(message, connection_type)


# Global connection manager
manager = ConnectionManager()


async def websocket_logs(websocket: WebSocket):
    """
    WebSocket endpoint for real-time logs
    
    Args:
        websocket: WebSocket connection
    """
    await manager.connect(websocket, "logs")
    
    try:
        while True:
            # Wait for messages from client
            data = await websocket.receive_text()
            
            # Echo back (for testing)
            await manager.send_personal_message(f"Echo: {data}", websocket)
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Log WebSocket disconnected")


async def websocket_attacks(websocket: WebSocket):
    """
    WebSocket endpoint for attack progress
    
    Args:
        websocket: WebSocket connection
    """
    await manager.connect(websocket, "attacks")
    
    try:
        while True:
            data = await websocket.receive_text()
            
            # Process attack updates
            try:
                message = json.loads(data)
                
                if message.get("type") == "subscribe":
                    # Subscribe to specific attack
                    attack_id = message.get("attack_id")
                    await manager.send_personal_message(
                        json.dumps({"status": "subscribed", "attack_id": attack_id}),
                        websocket
                    )
            except json.JSONDecodeError:
                pass
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Attack WebSocket disconnected")


async def websocket_agents(websocket: WebSocket):
    """
    WebSocket endpoint for agent status
    
    Args:
        websocket: WebSocket connection
    """
    await manager.connect(websocket, "agents")
    
    try:
        while True:
            data = await websocket.receive_text()
            
            # Process agent updates
            try:
                message = json.loads(data)
                
                if message.get("type") == "status_request":
                    # Send agent status
                    from api.routes.c2 import get_all_agents
                    
                    agents = await get_all_agents()
                    await manager.send_personal_message(
                        json.dumps({"type": "agent_status", "agents": agents}),
                        websocket
                    )
            except json.JSONDecodeError:
                pass
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Agent WebSocket disconnected")


async def websocket_general(websocket: WebSocket):
    """
    General WebSocket endpoint
    
    Args:
        websocket: WebSocket connection
    """
    await manager.connect(websocket, "general")
    
    try:
        while True:
            data = await websocket.receive_text()
            
            # Echo back
            await manager.send_personal_message(f"Received: {data}", websocket)
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("General WebSocket disconnected")


# Helper functions for broadcasting

async def broadcast_log(log_entry: Dict):
    """
    Broadcast log entry to all log subscribers
    
    Args:
        log_entry: Log entry data
    """
    await manager.broadcast_json({
        "type": "log",
        "data": log_entry
    }, "logs")


async def broadcast_attack_progress(attack_id: str, progress: Dict):
    """
    Broadcast attack progress to all attack subscribers
    
    Args:
        attack_id: Attack ID
        progress: Progress data
    """
    await manager.broadcast_json({
        "type": "attack_progress",
        "attack_id": attack_id,
        "data": progress
    }, "attacks")


async def broadcast_agent_status(agent_id: str, status: Dict):
    """
    Broadcast agent status to all agent subscribers
    
    Args:
        agent_id: Agent ID
        status: Status data
    """
    await manager.broadcast_json({
        "type": "agent_status",
        "agent_id": agent_id,
        "data": status
    }, "agents")


# Log streaming task
async def start_log_streaming():
    """
    Start streaming logs to WebSocket clients
    """
    import os
    
    log_file = "/tmp/manus_logs.txt"
    
    if not os.path.exists(log_file):
        # Create log file if not exists
        with open(log_file, 'w') as f:
            f.write("")
    
    last_position = 0
    
    while True:
        try:
            # Read new log entries
            with open(log_file, 'r') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                last_position = f.tell()
            
            # Broadcast new log entries
            for line in new_lines:
                if line.strip():
                    await broadcast_log({
                        "timestamp": asyncio.get_event_loop().time(),
                        "level": "info",
                        "source": "system",
                        "message": line.strip()
                    })
            
            # Wait before checking again
            await asyncio.sleep(1)
        
        except Exception as e:
            logger.error(f"Log streaming error: {e}")
            await asyncio.sleep(5)

