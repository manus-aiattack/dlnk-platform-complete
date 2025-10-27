"""
Alert Manager
"""

import asyncio
from typing import Dict, List, Callable
from datetime import datetime
import logging

log = logging.getLogger(__name__)


class Alert:
    """Represents an alert"""
    
    def __init__(self, severity: str, message: str, source: str):
        self.severity = severity
        self.message = message
        self.source = source
        self.timestamp = datetime.now()
        self.acknowledged = False
    
    def __repr__(self):
        return f"Alert({self.severity}, {self.message}, {self.source})"


class AlertManager:
    """Manages system alerts"""
    
    def __init__(self):
        self.alerts = []
        self.alert_handlers = []
        self.alert_history = []
    
    async def create_alert(self, severity: str, message: str, source: str):
        """Create a new alert"""
        
        alert = Alert(severity, message, source)
        self.alerts.append(alert)
        self.alert_history.append(alert)
        
        log.warning(f"[AlertManager] {severity} alert from {source}: {message}")
        
        # Trigger handlers
        for handler in self.alert_handlers:
            try:
                await handler(alert)
            except Exception as e:
                log.error(f"[AlertManager] Handler error: {e}")
    
    def register_handler(self, handler: Callable):
        """Register an alert handler"""
        self.alert_handlers.append(handler)
    
    async def acknowledge_alert(self, alert: Alert):
        """Acknowledge an alert"""
        alert.acknowledged = True
        
        if alert in self.alerts:
            self.alerts.remove(alert)
    
    async def get_active_alerts(self) -> List[Alert]:
        """Get active (unacknowledged) alerts"""
        return [a for a in self.alerts if not a.acknowledged]
    
    async def get_alerts_by_severity(self, severity: str) -> List[Alert]:
        """Get alerts by severity"""
        return [a for a in self.alerts if a.severity == severity]
    
    async def clear_acknowledged_alerts(self):
        """Clear acknowledged alerts"""
        self.alerts = [a for a in self.alerts if not a.acknowledged]
