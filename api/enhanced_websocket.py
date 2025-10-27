"""
Enhanced WebSocket Real-time Updates System
Phase 4: API & Backend Optimization - WebSocket Enhancement
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import uuid

from fastapi import WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
import redis.asyncio as aioredis

from core.enhanced_orchestrator import EnhancedOrchestrator
from core.ai_models.enhanced_ai_decision_engine import EnhancedAIDecisionEngine
from core.self_healing.enhanced_error_detector import EnhancedErrorDetector
from core.self_learning.enhanced_adaptive_learner import EnhancedAdaptiveLearner
from core.data_models import AttackPhase
from core.logger import log


@dataclass
class ClientConnection:
    """Client connection information"""
    websocket: WebSocket
    client_id: str
    session_id: str
    subscribed_channels: Set[str]
    connection_time: str
    last_activity: str
    user_agent: str = None
    ip_address: str = None


@dataclass
class WebSocketMessage:
    """WebSocket message structure"""
    type: str
    data: Dict[str, Any]
    timestamp: str
    client_id: str = None
    session_id: str = None
    message_id: str = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class ConnectionManager:
    """Enhanced WebSocket connection manager with Redis pub/sub"""

    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.active_connections: Dict[str, ClientConnection] = {}
        self.redis_url = redis_url
        self.redis: Optional[aioredis.Redis] = None
        self.pubsub: Optional[aioredis.PubSub] = None
        self.message_handlers: Dict[str, callable] = {}
        self.channel_subscriptions: Dict[str, Set[str]] = {}
        self.connection_lock = asyncio.Lock()

    async def connect(self):
        """Connect to Redis and initialize pub/sub"""
        try:
            self.redis = aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            self.pubsub = self.redis.pubsub()
            await self.pubsub.subscribe("global", "attacks", "agents", "system")

            # Start listening for Redis messages
            self._start_redis_listener()

            log.success("WebSocket ConnectionManager connected to Redis")
        except Exception as e:
            log.error(f"Failed to connect to Redis: {e}")

    def _start_redis_listener(self):
        """Start listening for Redis pub/sub messages"""
        async def listener():
            try:
                async for message in self.pubsub.listen():
                    if message['type'] == 'message':
                        channel = message['channel']
                        data = json.loads(message['data'])

                        # Forward to WebSocket clients
                        await self._forward_to_websockets(channel, data)
            except Exception as e:
                log.error(f"Redis listener error: {e}")

        asyncio.create_task(listener())

    async def _forward_to_websockets(self, channel: str, data: Dict[str, Any]):
        """Forward Redis messages to WebSocket clients"""
        try:
            # Find clients subscribed to this channel
            for client_id, connection in self.active_connections.items():
                if channel in connection.subscribed_channels:
                    message = WebSocketMessage(
                        type=f"channel.{channel}",
                        data=data,
                        timestamp=datetime.now().isoformat(),
                        client_id=client_id,
                        message_id=str(uuid.uuid4())
                    )

                    try:
                        await connection.websocket.send_text(json.dumps(message.to_dict()))
                    except Exception as e:
                        log.warning(f"Failed to send to client {client_id}: {e}")
                        await self.disconnect(client_id)
        except Exception as e:
            log.error(f"Error forwarding Redis message: {e}")

    async def connect_client(
        self,
        websocket: WebSocket,
        client_id: str,
        user_agent: str = None,
        ip_address: str = None
    ) -> ClientConnection:
        """Connect a new WebSocket client"""
        async with self.connection_lock:
            await websocket.accept()

            session_id = str(uuid.uuid4())
            connection = ClientConnection(
                websocket=websocket,
                client_id=client_id,
                session_id=session_id,
                subscribed_channels=set(),
                connection_time=datetime.now().isoformat(),
                last_activity=datetime.now().isoformat(),
                user_agent=user_agent,
                ip_address=ip_address
            )

            self.active_connections[client_id] = connection

            # Send welcome message
            welcome_message = WebSocketMessage(
                type="connection.welcome",
                data={
                    "client_id": client_id,
                    "session_id": session_id,
                    "server_time": datetime.now().isoformat(),
                    "features": [
                        "realtime_attacks",
                        "agent_status",
                        "system_monitoring",
                        "performance_metrics"
                    ]
                },
                timestamp=datetime.now().isoformat(),
                message_id=str(uuid.uuid4())
            )

            await websocket.send_text(json.dumps(welcome_message.to_dict()))

            log.info(f"Client {client_id} connected via WebSocket")
            return connection

    async def disconnect(self, client_id: str):
        """Disconnect a client"""
        async with self.connection_lock:
            if client_id in self.active_connections:
                connection = self.active_connections[client_id]

                # Unsubscribe from channels
                for channel in connection.subscribed_channels:
                    if channel in self.channel_subscriptions:
                        self.channel_subscriptions[channel].discard(client_id)

                # Close WebSocket
                try:
                    await connection.websocket.close()
                except Exception as e:
                    log.warning(f"Error closing WebSocket for {client_id}: {e}")

                # Remove from active connections
                del self.active_connections[client_id]

                # Send disconnect notification
                disconnect_message = WebSocketMessage(
                    type="connection.disconnected",
                    data={"client_id": client_id, "session_id": connection.session_id},
                    timestamp=datetime.now().isoformat(),
                    message_id=str(uuid.uuid4())
                )

                await self._publish_to_redis("global", disconnect_message.to_dict())

                log.info(f"Client {client_id} disconnected")

    async def subscribe_to_channel(self, client_id: str, channel: str) -> bool:
        """Subscribe client to a channel"""
        if client_id not in self.active_connections:
            return False

        connection = self.active_connections[client_id]
        connection.subscribed_channels.add(channel)

        # Track channel subscriptions
        if channel not in self.channel_subscriptions:
            self.channel_subscriptions[channel] = set()
        self.channel_subscriptions[channel].add(client_id)

        # Send subscription confirmation
        confirmation_message = WebSocketMessage(
            type="channel.subscribed",
            data={"channel": channel, "client_id": client_id},
            timestamp=datetime.now().isoformat(),
            client_id=client_id,
            message_id=str(uuid.uuid4())
        )

        try:
            await connection.websocket.send_text(json.dumps(confirmation_message.to_dict()))
            connection.last_activity = datetime.now().isoformat()
            return True
        except Exception as e:
            log.warning(f"Failed to send subscription confirmation: {e}")
            return False

    async def unsubscribe_from_channel(self, client_id: str, channel: str) -> bool:
        """Unsubscribe client from a channel"""
        if client_id not in self.active_connections:
            return False

        connection = self.active_connections[client_id]

        if channel in connection.subscribed_channels:
            connection.subscribed_channels.remove(channel)

            # Update channel subscriptions
            if channel in self.channel_subscriptions:
                self.channel_subscriptions[channel].discard(client_id)
                if not self.channel_subscriptions[channel]:
                    del self.channel_subscriptions[channel]

            # Send unsubscription confirmation
            confirmation_message = WebSocketMessage(
                type="channel.unsubscribed",
                data={"channel": channel, "client_id": client_id},
                timestamp=datetime.now().isoformat(),
                client_id=client_id,
                message_id=str(uuid.uuid4())
            )

            try:
                await connection.websocket.send_text(json.dumps(confirmation_message.to_dict()))
                connection.last_activity = datetime.now().isoformat()
                return True
            except Exception as e:
                log.warning(f"Failed to send unsubscription confirmation: {e}")

        return False

    async def send_personal_message(self, message: WebSocketMessage, client_id: str):
        """Send personal message to client"""
        if client_id in self.active_connections:
            connection = self.active_connections[client_id]

            try:
                await connection.websocket.send_text(json.dumps(message.to_dict()))
                connection.last_activity = datetime.now().isoformat()
                return True
            except Exception as e:
                log.warning(f"Failed to send personal message to {client_id}: {e}")
                await self.disconnect(client_id)
                return False
        return False

    async def broadcast(self, message: WebSocketMessage, exclude_clients: List[str] = None):
        """Broadcast message to all connected clients"""
        exclude_clients = exclude_clients or []

        success_count = 0
        for client_id, connection in self.active_connections.items():
            if client_id not in exclude_clients:
                try:
                    await connection.websocket.send_text(json.dumps(message.to_dict()))
                    connection.last_activity = datetime.now().isoformat()
                    success_count += 1
                except Exception as e:
                    log.warning(f"Failed to broadcast to {client_id}: {e}")
                    await self.disconnect(client_id)

        log.info(f"Broadcast message sent to {success_count} clients")
        return success_count

    async def _publish_to_redis(self, channel: str, message: Dict[str, Any]):
        """Publish message to Redis pub/sub"""
        try:
            if self.redis:
                await self.redis.publish(channel, json.dumps(message))
        except Exception as e:
            log.error(f"Failed to publish to Redis channel {channel}: {e}")

    async def publish_message(self, channel: str, message: Dict[str, Any], include_websocket: bool = True):
        """Publish message to channel (both Redis and WebSocket)"""
        # Publish to Redis
        await self._publish_to_redis(channel, message)

        # Optionally send via WebSocket
        if include_websocket:
            message_data = WebSocketMessage(
                type=f"channel.{channel}",
                data=message,
                timestamp=datetime.now().isoformat(),
                message_id=str(uuid.uuid4())
            )

            await self.broadcast(message_data)

    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        total_clients = len(self.active_connections)
        channel_stats = {
            channel: len(clients)
            for channel, clients in self.channel_subscriptions.items()
        }

        return {
            "total_connections": total_clients,
            "channels": channel_stats,
            "active_channels": list(self.channel_subscriptions.keys()),
            "timestamp": datetime.now().isoformat()
        }


class RealtimeAttackMonitor:
    """Real-time attack monitoring and updates"""

    def __init__(self, connection_manager: ConnectionManager):
        self.connection_manager = connection_manager
        self.attack_progress: Dict[str, Dict[str, Any]] = {}
        self.active_attacks: Set[str] = set()

    async def start_attack_monitoring(self, attack_id: str, target: Dict[str, Any]):
        """Start monitoring an attack"""
        self.active_attacks.add(attack_id)

        attack_info = {
            "attack_id": attack_id,
            "target": target,
            "start_time": datetime.now().isoformat(),
            "status": "initializing",
            "progress": 0,
            "phases": [],
            "agents": []
        }

        self.attack_progress[attack_id] = attack_info

        # Notify subscribed clients
        await self.connection_manager.publish_message(
            "attacks",
            {
                "event": "attack_started",
                "attack_id": attack_id,
                "target": target,
                "timestamp": datetime.now().isoformat()
            }
        )

    async def update_attack_progress(self, attack_id: str, phase: str, progress: float, status: str, details: Dict[str, Any] = None):
        """Update attack progress"""
        if attack_id not in self.attack_progress:
            return

        self.attack_progress[attack_id].update({
            "current_phase": phase,
            "progress": progress,
            "status": status,
            "last_update": datetime.now().isoformat()
        })

        if details:
            self.attack_progress[attack_id]["details"] = details

        # Send progress update
        progress_message = {
            "event": "attack_progress",
            "attack_id": attack_id,
            "phase": phase,
            "progress": progress,
            "status": status,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }

        await self.connection_manager.publish_message("attacks", progress_message)

    async def complete_attack(self, attack_id: str, success: bool, results: Dict[str, Any]):
        """Mark attack as completed"""
        if attack_id not in self.attack_progress:
            return

        self.attack_progress[attack_id].update({
            "status": "completed" if success else "failed",
            "success": success,
            "results": results,
            "end_time": datetime.now().isoformat(),
            "completed": True
        })

        # Remove from active attacks
        self.active_attacks.discard(attack_id)

        # Send completion message
        completion_message = {
            "event": "attack_completed",
            "attack_id": attack_id,
            "success": success,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }

        await self.connection_manager.publish_message("attacks", completion_message)

    async def get_attack_status(self, attack_id: str) -> Optional[Dict[str, Any]]:
        """Get current attack status"""
        return self.attack_progress.get(attack_id)

    async def get_all_attack_statuses(self) -> List[Dict[str, Any]]:
        """Get all attack statuses"""
        return list(self.attack_progress.values())


class RealtimeAgentMonitor:
    """Real-time agent monitoring and status updates"""

    def __init__(self, connection_manager: ConnectionManager):
        self.connection_manager = connection_manager
        self.agent_status: Dict[str, Dict[str, Any]] = {}
        self.agent_performance: Dict[str, List[Dict[str, Any]]] = {}

    async def update_agent_status(self, agent_name: str, status: str, details: Dict[str, Any] = None):
        """Update agent status"""
        timestamp = datetime.now().isoformat()

        self.agent_status[agent_name] = {
            "agent_name": agent_name,
            "status": status,
            "last_update": timestamp,
            "details": details or {}
        }

        # Store performance history
        if agent_name not in self.agent_performance:
            self.agent_performance[agent_name] = []

        self.agent_performance[agent_name].append({
            "timestamp": timestamp,
            "status": status,
            "details": details
        })

        # Keep only last 100 performance entries
        if len(self.agent_performance[agent_name]) > 100:
            self.agent_performance[agent_name].pop(0)

        # Send status update
        status_message = {
            "event": "agent_status_update",
            "agent_name": agent_name,
            "status": status,
            "details": details,
            "timestamp": timestamp
        }

        await self.connection_manager.publish_message("agents", status_message)

    async def get_agent_status(self, agent_name: str) -> Optional[Dict[str, Any]]:
        """Get agent status"""
        return self.agent_status.get(agent_name)

    async def get_all_agent_statuses(self) -> List[Dict[str, Any]]:
        """Get all agent statuses"""
        return list(self.agent_status.values())

    async def get_agent_performance_history(self, agent_name: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get agent performance history"""
        history = self.agent_performance.get(agent_name, [])
        return history[-limit:] if history else []


class RealtimeSystemMonitor:
    """Real-time system monitoring and health updates"""

    def __init__(self, connection_manager: ConnectionManager):
        self.connection_manager = connection_manager
        self.system_health: Dict[str, Any] = {
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "disk_usage": 0.0,
            "network_io": 0.0,
            "active_connections": 0,
            "error_rate": 0.0,
            "last_update": datetime.now().isoformat()
        }

    async def update_system_health(self, health_data: Dict[str, Any]):
        """Update system health metrics"""
        self.system_health.update(health_data)
        self.system_health["last_update"] = datetime.now().isoformat()

        # Send health update
        health_message = {
            "event": "system_health_update",
            "health_data": self.system_health,
            "timestamp": datetime.now().isoformat()
        }

        await self.connection_manager.publish_message("system", health_message)

    async def get_system_health(self) -> Dict[str, Any]:
        """Get current system health"""
        return self.system_health


# Enhanced WebSocket Handler
class EnhancedWebSocketHandler:
    """Enhanced WebSocket handler with advanced features"""

    def __init__(self, connection_manager: ConnectionManager):
        self.connection_manager = connection_manager
        self.attack_monitor = RealtimeAttackMonitor(connection_manager)
        self.agent_monitor = RealtimeAgentMonitor(connection_manager)
        self.system_monitor = RealtimeSystemMonitor(connection_manager)

    async def handle_websocket(self, websocket: WebSocket, client_id: str):
        """Handle WebSocket connection"""
        user_agent = websocket.headers.get("user-agent", "Unknown")
        ip_address = websocket.client.host if websocket.client else None

        try:
            # Connect client
            connection = await self.connection_manager.connect_client(
                websocket=websocket,
                client_id=client_id,
                user_agent=user_agent,
                ip_address=ip_address
            )

            # Subscribe to default channels
            await self.connection_manager.subscribe_to_channel(client_id, "system")
            await self.connection_manager.subscribe_to_channel(client_id, "attacks")

            # Send initial status
            initial_status = {
                "event": "initial_status",
                "system_health": await self.system_monitor.get_system_health(),
                "active_attacks": len(self.attack_monitor.active_attacks),
                "agent_count": len(self.agent_monitor.agent_status),
                "timestamp": datetime.now().isoformat()
            }

            await self.connection_manager.send_personal_message(
                WebSocketMessage(
                    type="status.initial",
                    data=initial_status,
                    timestamp=datetime.now().isoformat(),
                    message_id=str(uuid.uuid4())
                ),
                client_id
            )

            # Main message loop
            while True:
                try:
                    data = await websocket.receive_text()
                    message = json.loads(data)

                    await self._handle_client_message(connection, message)

                except WebSocketDisconnect:
                    break
                except json.JSONDecodeError:
                    # Send error message
                    error_message = WebSocketMessage(
                        type="error.invalid_json",
                        data={"error": "Invalid JSON format"},
                        timestamp=datetime.now().isoformat(),
                        message_id=str(uuid.uuid4())
                    )
                    await self.connection_manager.send_personal_message(error_message, client_id)

        except Exception as e:
            log.error(f"WebSocket handler error for {client_id}: {e}")
        finally:
            await self.connection_manager.disconnect(client_id)

    async def _handle_client_message(self, connection: ClientConnection, message: Dict[str, Any]):
        """Handle client message"""
        message_type = message.get("type", "")
        data = message.get("data", {})

        if message_type == "subscribe":
            channel = data.get("channel")
            if channel:
                await self.connection_manager.subscribe_to_channel(connection.client_id, channel)

        elif message_type == "unsubscribe":
            channel = data.get("channel")
            if channel:
                await self.connection_manager.unsubscribe_from_channel(connection.client_id, channel)

        elif message_type == "ping":
            # Send pong response
            pong_message = WebSocketMessage(
                type="pong",
                data={"timestamp": datetime.now().isoformat()},
                timestamp=datetime.now().isoformat(),
                client_id=connection.client_id,
                message_id=str(uuid.uuid4())
            )
            await self.connection_manager.send_personal_message(pong_message, connection.client_id)

        elif message_type == "get_attack_status":
            attack_id = data.get("attack_id")
            if attack_id:
                status = await self.attack_monitor.get_attack_status(attack_id)
                if status:
                    status_message = WebSocketMessage(
                        type="attack.status",
                        data=status,
                        timestamp=datetime.now().isoformat(),
                        client_id=connection.client_id,
                        message_id=str(uuid.uuid4())
                    )
                    await self.connection_manager.send_personal_message(status_message, connection.client_id)

        elif message_type == "get_agent_status":
            agent_name = data.get("agent_name")
            if agent_name:
                status = await self.agent_monitor.get_agent_status(agent_name)
                if status:
                    status_message = WebSocketMessage(
                        type="agent.status",
                        data=status,
                        timestamp=datetime.now().isoformat(),
                        client_id=connection.client_id,
                        message_id=str(uuid.uuid4())
                    )
                    await self.connection_manager.send_personal_message(status_message, connection.client_id)

        # Update last activity
        connection.last_activity = datetime.now().isoformat()

    async def get_monitor_stats(self) -> Dict[str, Any]:
        """Get monitor statistics"""
        return {
            "connection_stats": await self.connection_manager.get_connection_stats(),
            "attack_monitor_stats": {
                "active_attacks": len(self.attack_monitor.active_attacks),
                "total_attacks": len(self.attack_monitor.attack_progress)
            },
            "agent_monitor_stats": {
                "monitored_agents": len(self.agent_monitor.agent_status),
                "agents_with_history": len(self.agent_monitor.agent_performance)
            },
            "system_monitor_stats": {
                "health_last_update": self.system_monitor.system_health.get("last_update")
            }
        }


# Global instances
connection_manager = ConnectionManager()
websocket_handler = EnhancedWebSocketHandler(connection_manager)


# Utility functions for external use
async def initialize_websocket_system():
    """Initialize WebSocket system"""
    await connection_manager.connect()
    log.info("WebSocket system initialized")


async def send_attack_update(attack_id: str, phase: str, progress: float, status: str, details: Dict[str, Any] = None):
    """Send attack update from external systems"""
    await websocket_handler.attack_monitor.update_attack_progress(attack_id, phase, progress, status, details)


async def send_agent_status(agent_name: str, status: str, details: Dict[str, Any] = None):
    """Send agent status update from external systems"""
    await websocket_handler.agent_monitor.update_agent_status(agent_name, status, details)


async def send_system_health(health_data: Dict[str, Any]):
    """Send system health update from external systems"""
    await websocket_handler.system_monitor.update_system_health(health_data)


if __name__ == "__main__":
    # Test the WebSocket system
    async def test_websocket_system():
        await initialize_websocket_system()
        print("WebSocket system test completed")

    asyncio.run(test_websocket_system())