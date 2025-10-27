"""
Real-Time Monitoring System
WebSocket-based real-time updates for campaigns, agents, and attacks
"""

import asyncio
import json
from typing import Dict, List, Set, Any, Optional
from datetime import datetime
import logging
from collections import defaultdict

log = logging.getLogger(__name__)


class RealtimeMonitor:
    """
    Real-Time Monitoring System
    
    Features:
    - WebSocket connections management
    - Real-time campaign updates
    - Live log streaming
    - Agent status broadcasting
    - Alert notifications
    """
    
    def __init__(self):
        # WebSocket connections
        self.connections: Set[Any] = set()
        
        # Subscriptions (connection -> topics)
        self.subscriptions: Dict[Any, Set[str]] = defaultdict(set)
        
        # Campaign monitors
        self.campaign_monitors: Dict[str, List[Any]] = defaultdict(list)
        
        # Log buffers
        self.log_buffers: Dict[str, List[Dict]] = defaultdict(list)
        self.max_buffer_size = 1000
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'messages_sent': 0,
            'broadcasts': 0
        }
    
    async def register_connection(self, websocket: Any):
        """Register new WebSocket connection"""
        self.connections.add(websocket)
        self.stats['total_connections'] += 1
        self.stats['active_connections'] = len(self.connections)
        
        log.info(f"[RealtimeMonitor] New connection registered (total: {len(self.connections)})")
        
        # Send welcome message
        await self.send_to_connection(websocket, {
            'type': 'welcome',
            'message': 'Connected to dLNk Attack Platform',
            'timestamp': datetime.utcnow().isoformat()
        })
    
    async def unregister_connection(self, websocket: Any):
        """Unregister WebSocket connection"""
        if websocket in self.connections:
            self.connections.remove(websocket)
            
            # Remove from subscriptions
            if websocket in self.subscriptions:
                del self.subscriptions[websocket]
            
            # Remove from campaign monitors
            for monitors in self.campaign_monitors.values():
                if websocket in monitors:
                    monitors.remove(websocket)
            
            self.stats['active_connections'] = len(self.connections)
            
            log.info(f"[RealtimeMonitor] Connection unregistered (remaining: {len(self.connections)})")
    
    async def subscribe(self, websocket: Any, topics: List[str]):
        """Subscribe connection to topics"""
        self.subscriptions[websocket].update(topics)
        
        log.info(f"[RealtimeMonitor] Connection subscribed to {len(topics)} topics")
        
        await self.send_to_connection(websocket, {
            'type': 'subscription_confirmed',
            'topics': topics,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    async def unsubscribe(self, websocket: Any, topics: List[str]):
        """Unsubscribe connection from topics"""
        if websocket in self.subscriptions:
            self.subscriptions[websocket].difference_update(topics)
    
    async def send_to_connection(self, websocket: Any, message: Dict):
        """Send message to specific connection"""
        try:
            await websocket.send_json(message)
            self.stats['messages_sent'] += 1
        except Exception as e:
            log.error(f"[RealtimeMonitor] Failed to send message: {e}")
            await self.unregister_connection(websocket)
    
    async def broadcast(self, message: Dict, topic: Optional[str] = None):
        """
        Broadcast message to all connections or specific topic
        
        Args:
            message: Message to broadcast
            topic: Optional topic filter
        """
        if topic:
            # Send to subscribers of specific topic
            recipients = [
                ws for ws, topics in self.subscriptions.items()
                if topic in topics
            ]
        else:
            # Send to all connections
            recipients = list(self.connections)
        
        # Send to all recipients
        tasks = [
            self.send_to_connection(ws, message)
            for ws in recipients
        ]
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            self.stats['broadcasts'] += 1
            
            log.debug(f"[RealtimeMonitor] Broadcast to {len(recipients)} connections")
    
    async def broadcast_campaign_update(
        self,
        campaign_id: str,
        update_type: str,
        data: Dict[str, Any]
    ):
        """Broadcast campaign update"""
        message = {
            'type': 'campaign_update',
            'campaign_id': campaign_id,
            'update_type': update_type,
            'data': data,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Send to campaign monitors
        if campaign_id in self.campaign_monitors:
            tasks = [
                self.send_to_connection(ws, message)
                for ws in self.campaign_monitors[campaign_id]
            ]
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Also broadcast to 'campaigns' topic
        await self.broadcast(message, topic='campaigns')
    
    async def broadcast_agent_status(
        self,
        agent_name: str,
        status: str,
        details: Dict[str, Any]
    ):
        """Broadcast agent status update"""
        message = {
            'type': 'agent_status',
            'agent_name': agent_name,
            'status': status,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        await self.broadcast(message, topic='agents')
    
    async def stream_log(
        self,
        campaign_id: str,
        log_level: str,
        message: str,
        metadata: Optional[Dict] = None
    ):
        """Stream log message"""
        log_entry = {
            'type': 'log',
            'campaign_id': campaign_id,
            'level': log_level,
            'message': message,
            'metadata': metadata or {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Add to buffer
        self.log_buffers[campaign_id].append(log_entry)
        
        # Trim buffer if too large
        if len(self.log_buffers[campaign_id]) > self.max_buffer_size:
            self.log_buffers[campaign_id] = self.log_buffers[campaign_id][-self.max_buffer_size:]
        
        # Broadcast to campaign monitors
        if campaign_id in self.campaign_monitors:
            tasks = [
                self.send_to_connection(ws, log_entry)
                for ws in self.campaign_monitors[campaign_id]
            ]
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        details: Optional[Dict] = None
    ):
        """Send alert notification"""
        alert = {
            'type': 'alert',
            'alert_type': alert_type,
            'severity': severity,
            'message': message,
            'details': details or {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        await self.broadcast(alert, topic='alerts')
    
    async def monitor_campaign(self, websocket: Any, campaign_id: str):
        """Register connection to monitor specific campaign"""
        self.campaign_monitors[campaign_id].append(websocket)
        
        # Send recent logs
        if campaign_id in self.log_buffers:
            recent_logs = self.log_buffers[campaign_id][-100:]  # Last 100 logs
            
            for log_entry in recent_logs:
                await self.send_to_connection(websocket, log_entry)
        
        log.info(f"[RealtimeMonitor] Connection monitoring campaign: {campaign_id}")
    
    async def unmonitor_campaign(self, websocket: Any, campaign_id: str):
        """Unregister connection from campaign monitoring"""
        if campaign_id in self.campaign_monitors:
            if websocket in self.campaign_monitors[campaign_id]:
                self.campaign_monitors[campaign_id].remove(websocket)
    
    async def broadcast_progress(
        self,
        campaign_id: str,
        progress: float,
        current_task: str,
        completed_tasks: int,
        total_tasks: int
    ):
        """Broadcast campaign progress"""
        message = {
            'type': 'progress',
            'campaign_id': campaign_id,
            'progress': progress,
            'current_task': current_task,
            'completed_tasks': completed_tasks,
            'total_tasks': total_tasks,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        await self.broadcast_campaign_update(campaign_id, 'progress', message)
    
    async def broadcast_vulnerability_found(
        self,
        campaign_id: str,
        vulnerability: Dict[str, Any]
    ):
        """Broadcast vulnerability discovery"""
        message = {
            'type': 'vulnerability_found',
            'campaign_id': campaign_id,
            'vulnerability': vulnerability,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        await self.broadcast_campaign_update(campaign_id, 'vulnerability', message)
        
        # Also send alert for high severity
        if vulnerability.get('severity') in ['high', 'critical']:
            await self.send_alert(
                'vulnerability_found',
                vulnerability.get('severity', 'medium'),
                f"High severity vulnerability found: {vulnerability.get('title', 'Unknown')}",
                vulnerability
            )
    
    async def broadcast_exploit_success(
        self,
        campaign_id: str,
        exploit_info: Dict[str, Any]
    ):
        """Broadcast successful exploitation"""
        message = {
            'type': 'exploit_success',
            'campaign_id': campaign_id,
            'exploit': exploit_info,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        await self.broadcast_campaign_update(campaign_id, 'exploit', message)
        
        # Send alert
        await self.send_alert(
            'exploit_success',
            'high',
            f"Successful exploitation: {exploit_info.get('target', 'Unknown')}",
            exploit_info
        )
    
    async def get_campaign_logs(
        self,
        campaign_id: str,
        limit: int = 100
    ) -> List[Dict]:
        """Get campaign logs"""
        if campaign_id in self.log_buffers:
            return self.log_buffers[campaign_id][-limit:]
        return []
    
    def get_stats(self) -> Dict:
        """Get monitoring statistics"""
        return {
            **self.stats,
            'monitored_campaigns': len(self.campaign_monitors),
            'total_subscriptions': sum(len(topics) for topics in self.subscriptions.values())
        }


# Global monitor instance
_monitor = None


def get_monitor() -> RealtimeMonitor:
    """Get global monitor instance"""
    global _monitor
    if _monitor is None:
        _monitor = RealtimeMonitor()
    return _monitor

