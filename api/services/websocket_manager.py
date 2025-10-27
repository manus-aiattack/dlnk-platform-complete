"""
WebSocket Manager
จัดการ WebSocket connections สำหรับ real-time updates
"""

from fastapi import WebSocket
from typing import Dict, List, Set
import json
from core.logger import log


class WebSocketManager:
    """WebSocket connection manager"""
    
    def __init__(self):
        # attack_id -> list of websockets
        self.attack_connections: Dict[str, List[WebSocket]] = {}
        
        # System monitoring connections (admin only)
        self.system_connections: Set[WebSocket] = set()
    
    async def connect(self, websocket: WebSocket, attack_id: str):
        """Connect websocket to attack channel"""
        await websocket.accept()
        
        if attack_id not in self.attack_connections:
            self.attack_connections[attack_id] = []
        
        self.attack_connections[attack_id].append(websocket)
        log.info(f"[WebSocket] Client connected to attack {attack_id}")
    
    def disconnect(self, websocket: WebSocket, attack_id: str):
        """Disconnect websocket from attack channel"""
        if attack_id in self.attack_connections:
            if websocket in self.attack_connections[attack_id]:
                self.attack_connections[attack_id].remove(websocket)
                log.info(f"[WebSocket] Client disconnected from attack {attack_id}")
            
            # Clean up empty lists
            if not self.attack_connections[attack_id]:
                del self.attack_connections[attack_id]
    
    async def connect_system(self, websocket: WebSocket):
        """Connect websocket to system monitoring channel"""
        await websocket.accept()
        self.system_connections.add(websocket)
        log.info("[WebSocket] Client connected to system monitoring")
    
    def disconnect_system(self, websocket: WebSocket):
        """Disconnect websocket from system monitoring channel"""
        if websocket in self.system_connections:
            self.system_connections.remove(websocket)
            log.info("[WebSocket] Client disconnected from system monitoring")
    
    async def broadcast_to_attack(self, attack_id: str, message: Dict):
        """Broadcast message to all clients watching this attack"""
        if attack_id in self.attack_connections:
            disconnected = []
            
            for websocket in self.attack_connections[attack_id]:
                try:
                    await websocket.send_json(message)
                except Exception as e:
                    log.error(f"[WebSocket] Failed to send to client: {e}")
                    disconnected.append(websocket)
            
            # Remove disconnected clients
            for websocket in disconnected:
                self.disconnect(websocket, attack_id)
    
    async def broadcast_system(self, message: Dict):
        """Broadcast message to all system monitoring clients"""
        disconnected = []
        
        for websocket in self.system_connections:
            try:
                await websocket.send_json(message)
            except Exception as e:
                log.error(f"[WebSocket] Failed to send to system client: {e}")
                disconnected.add(websocket)
        
        # Remove disconnected clients
        for websocket in disconnected:
            self.disconnect_system(websocket)


# Global websocket manager instance
ws_manager = WebSocketManager()
