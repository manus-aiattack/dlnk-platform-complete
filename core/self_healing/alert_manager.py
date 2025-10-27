"""
Alert Manager for dLNk Attack Platform
Manages alerts and notifications for system issues
"""

import asyncio
import json
from typing import Dict, List, Optional, Callable
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
import logging

log = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertCategory(Enum):
    """Alert categories"""
    HEALTH = "HEALTH"
    PERFORMANCE = "PERFORMANCE"
    RESOURCE = "RESOURCE"
    SECURITY = "SECURITY"
    SYSTEM = "SYSTEM"


class AlertManager:
    """
    Alert and Notification Management System
    
    Features:
    - Create and manage alerts
    - Multiple notification channels
    - Alert deduplication
    - Alert aggregation
    - Alert history
    - Escalation rules
    - Notification rate limiting
    """
    
    def __init__(self):
        self.alerts = []
        self.alert_history = []
        self.notification_channels = {}
        self.escalation_rules = {}
        self.deduplication_window = 300  # 5 minutes
        self.max_history = 1000
        
        # Alert counters
        self.alert_counts = defaultdict(int)
        
        # Rate limiting
        self.rate_limits = {}
        self.last_notification = {}
        
        # Alert handlers
        self.alert_handlers = []
    
    async def create_alert(
        self,
        title: str,
        message: str,
        severity: AlertSeverity,
        category: AlertCategory,
        metadata: Optional[Dict] = None,
        auto_notify: bool = True
    ) -> Dict:
        """
        Create a new alert
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity level
            category: Alert category
            metadata: Additional metadata
            auto_notify: Automatically send notifications
        
        Returns:
            Created alert
        """
        alert = {
            'id': self._generate_alert_id(),
            'title': title,
            'message': message,
            'severity': severity.value,
            'category': category.value,
            'metadata': metadata or {},
            'timestamp': datetime.now(),
            'acknowledged': False,
            'resolved': False
        }
        
        # Check for duplicates
        if self._is_duplicate(alert):
            log.debug(f"[AlertManager] Duplicate alert suppressed: {title}")
            return {'status': 'suppressed', 'reason': 'duplicate'}
        
        # Add to active alerts
        self.alerts.append(alert)
        self.alert_counts[severity.value] += 1
        
        log.info(
            f"[AlertManager] Alert created: {title} "
            f"(severity: {severity.value}, category: {category.value})"
        )
        
        # Call alert handlers
        for handler in self.alert_handlers:
            try:
                await handler(alert)
            except Exception as e:
                log.error(f"[AlertManager] Alert handler error: {e}")
        
        # Send notifications
        if auto_notify:
            await self._send_notifications(alert)
        
        # Check escalation rules
        await self._check_escalation(alert)
        
        return alert
    
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def _is_duplicate(self, alert: Dict) -> bool:
        """Check if alert is a duplicate within deduplication window"""
        cutoff_time = datetime.now() - timedelta(seconds=self.deduplication_window)
        
        for existing_alert in self.alerts:
            if existing_alert['resolved']:
                continue
            
            if existing_alert['timestamp'] < cutoff_time:
                continue
            
            # Check if same title and category
            if (existing_alert['title'] == alert['title'] and
                existing_alert['category'] == alert['category']):
                return True
        
        return False
    
    async def _send_notifications(self, alert: Dict):
        """Send notifications through registered channels"""
        severity = alert['severity']
        
        # Check rate limiting
        if not self._check_rate_limit(alert):
            log.debug(f"[AlertManager] Notification rate limited for: {alert['title']}")
            return
        
        # Send to appropriate channels based on severity
        for channel_name, channel in self.notification_channels.items():
            if self._should_notify_channel(channel, alert):
                try:
                    await channel['handler'](alert)
                    log.info(f"[AlertManager] Notification sent via {channel_name}")
                except Exception as e:
                    log.error(f"[AlertManager] Notification failed for {channel_name}: {e}")
    
    def _check_rate_limit(self, alert: Dict) -> bool:
        """Check if alert passes rate limiting"""
        key = f"{alert['category']}:{alert['title']}"
        
        if key in self.rate_limits:
            limit = self.rate_limits[key]
            last_time = self.last_notification.get(key, 0)
            
            if time.time() - last_time < limit:
                return False
        
        self.last_notification[key] = time.time()
        return True
    
    def _should_notify_channel(self, channel: Dict, alert: Dict) -> bool:
        """Determine if channel should receive this alert"""
        # Check severity threshold
        severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        channel_threshold = channel.get('min_severity', 'INFO')
        alert_severity = alert['severity']
        
        if severity_order.index(alert_severity) < severity_order.index(channel_threshold):
            return False
        
        # Check category filter
        if 'categories' in channel:
            if alert['category'] not in channel['categories']:
                return False
        
        return True
    
    async def _check_escalation(self, alert: Dict):
        """Check and apply escalation rules"""
        severity = alert['severity']
        category = alert['category']
        
        key = f"{category}:{severity}"
        
        if key in self.escalation_rules:
            rule = self.escalation_rules[key]
            
            # Count recent similar alerts
            recent_count = self._count_recent_alerts(category, severity, rule['window'])
            
            if recent_count >= rule['threshold']:
                log.warning(
                    f"[AlertManager] Escalation triggered: {recent_count} {severity} "
                    f"alerts in {rule['window']}s"
                )
                
                # Create escalated alert
                await self.create_alert(
                    title=f"ESCALATION: Multiple {severity} alerts",
                    message=f"{recent_count} {severity} alerts in {category} category",
                    severity=AlertSeverity.CRITICAL,
                    category=AlertCategory.SYSTEM,
                    metadata={'escalated_from': key, 'count': recent_count},
                    auto_notify=True
                )
    
    def _count_recent_alerts(
        self,
        category: str,
        severity: str,
        window: int
    ) -> int:
        """Count recent alerts matching criteria"""
        cutoff_time = datetime.now() - timedelta(seconds=window)
        
        count = 0
        for alert in self.alerts:
            if alert['timestamp'] >= cutoff_time:
                if alert['category'] == category and alert['severity'] == severity:
                    count += 1
        
        return count
    
    async def acknowledge_alert(self, alert_id: str, user: str = 'system') -> bool:
        """
        Acknowledge an alert
        
        Args:
            alert_id: Alert ID
            user: User acknowledging the alert
        
        Returns:
            Success status
        """
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['acknowledged'] = True
                alert['acknowledged_by'] = user
                alert['acknowledged_at'] = datetime.now()
                
                log.info(f"[AlertManager] Alert acknowledged: {alert['title']} by {user}")
                return True
        
        return False
    
    async def resolve_alert(self, alert_id: str, resolution: str = '') -> bool:
        """
        Resolve an alert
        
        Args:
            alert_id: Alert ID
            resolution: Resolution notes
        
        Returns:
            Success status
        """
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['resolved'] = True
                alert['resolution'] = resolution
                alert['resolved_at'] = datetime.now()
                
                # Move to history
                self.alert_history.append(alert)
                
                # Keep history size manageable
                if len(self.alert_history) > self.max_history:
                    self.alert_history = self.alert_history[-self.max_history:]
                
                log.info(f"[AlertManager] Alert resolved: {alert['title']}")
                return True
        
        return False
    
    def register_notification_channel(
        self,
        name: str,
        handler: Callable,
        min_severity: str = 'INFO',
        categories: Optional[List[str]] = None
    ):
        """
        Register a notification channel
        
        Args:
            name: Channel name
            handler: Async function to handle notifications
            min_severity: Minimum severity to notify
            categories: List of categories to notify (None = all)
        """
        self.notification_channels[name] = {
            'handler': handler,
            'min_severity': min_severity,
            'categories': categories
        }
        
        log.info(f"[AlertManager] Registered notification channel: {name}")
    
    def register_alert_handler(self, handler: Callable):
        """Register a handler to be called when alerts are created"""
        self.alert_handlers.append(handler)
        log.info("[AlertManager] Registered alert handler")
    
    def set_escalation_rule(
        self,
        category: str,
        severity: str,
        threshold: int,
        window: int
    ):
        """
        Set an escalation rule
        
        Args:
            category: Alert category
            severity: Alert severity
            threshold: Number of alerts to trigger escalation
            window: Time window in seconds
        """
        key = f"{category}:{severity}"
        self.escalation_rules[key] = {
            'threshold': threshold,
            'window': window
        }
        
        log.info(
            f"[AlertManager] Set escalation rule: {threshold} {severity} "
            f"alerts in {window}s triggers escalation"
        )
    
    def set_rate_limit(self, category: str, title: str, limit_seconds: int):
        """Set rate limit for specific alert type"""
        key = f"{category}:{title}"
        self.rate_limits[key] = limit_seconds
        
        log.info(f"[AlertManager] Set rate limit for {key}: {limit_seconds}s")
    
    def get_active_alerts(
        self,
        severity: Optional[str] = None,
        category: Optional[str] = None
    ) -> List[Dict]:
        """
        Get active (unresolved) alerts
        
        Args:
            severity: Filter by severity
            category: Filter by category
        
        Returns:
            List of active alerts
        """
        alerts = [a for a in self.alerts if not a['resolved']]
        
        if severity:
            alerts = [a for a in alerts if a['severity'] == severity]
        
        if category:
            alerts = [a for a in alerts if a['category'] == category]
        
        return alerts
    
    def get_alert_statistics(self) -> Dict:
        """Get alert statistics"""
        active_alerts = [a for a in self.alerts if not a['resolved']]
        
        stats = {
            'total_active': len(active_alerts),
            'total_history': len(self.alert_history),
            'by_severity': {
                'CRITICAL': len([a for a in active_alerts if a['severity'] == 'CRITICAL']),
                'HIGH': len([a for a in active_alerts if a['severity'] == 'HIGH']),
                'MEDIUM': len([a for a in active_alerts if a['severity'] == 'MEDIUM']),
                'LOW': len([a for a in active_alerts if a['severity'] == 'LOW']),
                'INFO': len([a for a in active_alerts if a['severity'] == 'INFO'])
            },
            'by_category': {},
            'acknowledged': len([a for a in active_alerts if a['acknowledged']]),
            'unacknowledged': len([a for a in active_alerts if not a['acknowledged']])
        }
        
        # Count by category
        for alert in active_alerts:
            category = alert['category']
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
        
        return stats
    
    def clear_resolved_alerts(self):
        """Remove resolved alerts from active list"""
        self.alerts = [a for a in self.alerts if not a['resolved']]
        log.info("[AlertManager] Cleared resolved alerts")


# Pre-defined notification handlers
class NotificationHandlers:
    """Collection of notification handlers"""
    
    @staticmethod
    async def log_handler(alert: Dict):
        """Log notification handler"""
        log.info(
            f"[ALERT] {alert['severity']} - {alert['title']}: {alert['message']}"
        )
    
    @staticmethod
    async def console_handler(alert: Dict):
        """Console notification handler"""
        print(f"\n{'='*60}")
        print(f"ALERT: {alert['title']}")
        print(f"Severity: {alert['severity']}")
        print(f"Category: {alert['category']}")
        print(f"Message: {alert['message']}")
        print(f"Time: {alert['timestamp']}")
        print(f"{'='*60}\n")
    
    @staticmethod
    async def file_handler(alert: Dict, filepath: str = '/tmp/alerts.log'):
        """File notification handler"""
        try:
            with open(filepath, 'a') as f:
                f.write(json.dumps({
                    **alert,
                    'timestamp': alert['timestamp'].isoformat()
                }) + '\n')
        except Exception as e:
            log.error(f"[AlertManager] File handler error: {e}")
    
    @staticmethod
    async def webhook_handler(alert: Dict, webhook_url: str):
        """Webhook notification handler"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                payload = {
                    'title': alert['title'],
                    'message': alert['message'],
                    'severity': alert['severity'],
                    'category': alert['category'],
                    'timestamp': alert['timestamp'].isoformat()
                }
                
                async with session.post(webhook_url, json=payload, timeout=10) as response:
                    if response.status == 200:
                        log.info("[AlertManager] Webhook notification sent")
                    else:
                        log.error(f"[AlertManager] Webhook failed: {response.status}")
        except Exception as e:
            log.error(f"[AlertManager] Webhook handler error: {e}")


if __name__ == '__main__':
    import time
    
    async def test():
        """Test alert manager"""
        manager = AlertManager()
        
        # Register notification channels
        manager.register_notification_channel(
            'console',
            NotificationHandlers.console_handler,
            min_severity='MEDIUM'
        )
        
        manager.register_notification_channel(
            'log',
            NotificationHandlers.log_handler,
            min_severity='INFO'
        )
        
        # Set escalation rule
        manager.set_escalation_rule('HEALTH', 'HIGH', threshold=3, window=60)
        
        # Create some alerts
        await manager.create_alert(
            title="API Server Slow",
            message="API response time exceeded 2 seconds",
            severity=AlertSeverity.MEDIUM,
            category=AlertCategory.PERFORMANCE
        )
        
        await manager.create_alert(
            title="High CPU Usage",
            message="CPU usage at 95%",
            severity=AlertSeverity.HIGH,
            category=AlertCategory.RESOURCE
        )
        
        await manager.create_alert(
            title="Database Connection Failed",
            message="Unable to connect to database",
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.HEALTH
        )
        
        # Get statistics
        stats = manager.get_alert_statistics()
        print("\n[+] Alert Statistics:")
        print(f"  Total Active: {stats['total_active']}")
        print(f"  By Severity: {stats['by_severity']}")
        print(f"  By Category: {stats['by_category']}")
        
        # Get active alerts
        active = manager.get_active_alerts()
        print(f"\n[+] Active Alerts: {len(active)}")
        for alert in active:
            print(f"  - {alert['severity']}: {alert['title']}")
        
        # Acknowledge an alert
        if active:
            await manager.acknowledge_alert(active[0]['id'], user='admin')
        
        # Resolve an alert
        if active:
            await manager.resolve_alert(active[0]['id'], resolution='Fixed manually')
        
        print(f"\n[+] After resolution:")
        stats = manager.get_alert_statistics()
        print(f"  Total Active: {stats['total_active']}")
        print(f"  Total History: {stats['total_history']}")
    
    asyncio.run(test())

