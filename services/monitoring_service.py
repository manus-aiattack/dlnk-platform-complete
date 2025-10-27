#!/usr/bin/env python3
"""
dLNk Attack Platform - Production Monitoring Service
Comprehensive monitoring, logging, and alerting system
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import psutil
import aiohttp
import asyncpg
from dataclasses import dataclass, asdict
from enum import Enum

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.logger import log


class AlertLevel(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class Alert:
    level: AlertLevel
    message: str
    component: str
    timestamp: datetime
    metadata: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "message": self.message,
            "component": self.component,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata or {}
        }


class MetricsCollector:
    """Collects system and application metrics"""
    
    def __init__(self):
        self.metrics = {}
    
    async def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system-level metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Network metrics
            network = psutil.net_io_counters()
            
            return {
                "timestamp": datetime.now().isoformat(),
                "cpu": {
                    "percent": cpu_percent,
                    "count": cpu_count,
                    "load_avg": os.getloadavg() if hasattr(os, 'getloadavg') else None
                },
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "percent": memory.percent,
                    "used": memory.used
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": disk.percent
                },
                "network": {
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv,
                    "packets_sent": network.packets_sent,
                    "packets_recv": network.packets_recv
                }
            }
        except Exception as e:
            log.error(f"Error collecting system metrics: {e}")
            return {}
    
    async def collect_application_metrics(self, db: asyncpg.Connection) -> Dict[str, Any]:
        """Collect application-level metrics"""
        try:
            # Database metrics
            db_health = await db.fetchval("SELECT check_database_health()")
            
            # Active attacks count
            active_attacks = await db.fetchval("""
                SELECT COUNT(*) FROM attacks 
                WHERE status IN ('pending', 'running', 'analyzing')
            """)
            
            # API usage metrics
            api_usage = await db.fetchval("""
                SELECT COUNT(*) FROM key_usage_logs 
                WHERE timestamp > NOW() - INTERVAL '1 hour'
            """)
            
            # Error rate
            error_rate = await db.fetchval("""
                SELECT COUNT(*) FROM key_usage_logs 
                WHERE response_status >= 400 
                AND timestamp > NOW() - INTERVAL '1 hour'
            """)
            
            return {
                "timestamp": datetime.now().isoformat(),
                "database": json.loads(db_health) if db_health else {},
                "attacks": {
                    "active": active_attacks,
                    "total_today": await db.fetchval("""
                        SELECT COUNT(*) FROM attacks 
                        WHERE DATE(started_at) = CURRENT_DATE
                    """)
                },
                "api": {
                    "requests_last_hour": api_usage,
                    "error_rate": error_rate,
                    "success_rate": max(0, 100 - (error_rate / max(api_usage, 1)) * 100)
                }
            }
        except Exception as e:
            log.error(f"Error collecting application metrics: {e}")
            return {}


class AlertManager:
    """Manages alerts and notifications"""
    
    def __init__(self):
        self.alert_history: List[Alert] = []
        self.alert_rules = self._load_alert_rules()
    
    def _load_alert_rules(self) -> Dict[str, Dict]:
        """Load alert rules from configuration"""
        return {
            "cpu_high": {
                "threshold": 80,
                "level": AlertLevel.WARNING,
                "message": "High CPU usage detected"
            },
            "memory_high": {
                "threshold": 85,
                "level": AlertLevel.WARNING,
                "message": "High memory usage detected"
            },
            "disk_full": {
                "threshold": 90,
                "level": AlertLevel.CRITICAL,
                "message": "Disk space critically low"
            },
            "error_rate_high": {
                "threshold": 10,
                "level": AlertLevel.ERROR,
                "message": "High error rate detected"
            },
            "database_down": {
                "level": AlertLevel.CRITICAL,
                "message": "Database connection failed"
            },
            "no_active_attacks": {
                "threshold": 0,
                "level": AlertLevel.INFO,
                "message": "No active attacks"
            }
        }
    
    async def check_alerts(self, metrics: Dict[str, Any]) -> List[Alert]:
        """Check metrics against alert rules"""
        alerts = []
        
        # System alerts
        if "cpu" in metrics:
            cpu_percent = metrics["cpu"].get("percent", 0)
            if cpu_percent > self.alert_rules["cpu_high"]["threshold"]:
                alerts.append(Alert(
                    level=self.alert_rules["cpu_high"]["level"],
                    message=f"{self.alert_rules['cpu_high']['message']}: {cpu_percent}%",
                    component="system",
                    timestamp=datetime.now(),
                    metadata={"cpu_percent": cpu_percent}
                ))
        
        if "memory" in metrics:
            memory_percent = metrics["memory"].get("percent", 0)
            if memory_percent > self.alert_rules["memory_high"]["threshold"]:
                alerts.append(Alert(
                    level=self.alert_rules["memory_high"]["level"],
                    message=f"{self.alert_rules['memory_high']['message']}: {memory_percent}%",
                    component="system",
                    timestamp=datetime.now(),
                    metadata={"memory_percent": memory_percent}
                ))
        
        if "disk" in metrics:
            disk_percent = metrics["disk"].get("percent", 0)
            if disk_percent > self.alert_rules["disk_full"]["threshold"]:
                alerts.append(Alert(
                    level=self.alert_rules["disk_full"]["level"],
                    message=f"{self.alert_rules['disk_full']['message']}: {disk_percent}%",
                    component="system",
                    timestamp=datetime.now(),
                    metadata={"disk_percent": disk_percent}
                ))
        
        # Application alerts
        if "api" in metrics:
            error_rate = metrics["api"].get("error_rate", 0)
            if error_rate > self.alert_rules["error_rate_high"]["threshold"]:
                alerts.append(Alert(
                    level=self.alert_rules["error_rate_high"]["level"],
                    message=f"{self.alert_rules['error_rate_high']['message']}: {error_rate}%",
                    component="api",
                    timestamp=datetime.now(),
                    metadata={"error_rate": error_rate}
                ))
        
        return alerts
    
    async def send_notifications(self, alerts: List[Alert]):
        """Send notifications for alerts"""
        for alert in alerts:
            # Log alert
            log_level = {
                AlertLevel.INFO: log.info,
                AlertLevel.WARNING: log.warning,
                AlertLevel.ERROR: log.error,
                AlertLevel.CRITICAL: log.critical
            }.get(alert.level, log.info)
            
            log_level(f"[ALERT] {alert.component}: {alert.message}")
            
            # Store in history
            self.alert_history.append(alert)
            
            # Send external notifications (email, webhook, etc.)
            await self._send_external_notification(alert)
    
    async def _send_external_notification(self, alert: Alert):
        """Send external notifications"""
        try:
            # Email notification
            if os.getenv("NOTIFICATION_EMAIL_ENABLED", "false").lower() == "true":
                await self._send_email_alert(alert)
            
            # Webhook notification
            webhook_url = os.getenv("ALERT_WEBHOOK_URL", "")
            if webhook_url:
                await self._send_webhook_alert(alert, webhook_url)
            
            # Telegram notification
            telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
            telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
            if telegram_token and telegram_chat_id:
                await self._send_telegram_alert(alert, telegram_token, telegram_chat_id)
        
        except Exception as e:
            log.error(f"Error sending external notification: {e}")
    
    async def _send_email_alert(self, alert: Alert):
        """Send email alert"""
        # Implementation for email alerts
        pass
    
    async def _send_webhook_alert(self, alert: Alert, webhook_url: str):
        """Send webhook alert"""
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(webhook_url, json=alert.to_dict())
        except Exception as e:
            log.error(f"Error sending webhook alert: {e}")
    
    async def _send_telegram_alert(self, alert: Alert, token: str, chat_id: str):
        """Send Telegram alert"""
        try:
            message = f"🚨 *{alert.level.value.upper()}*\n"
            message += f"Component: {alert.component}\n"
            message += f"Message: {alert.message}\n"
            message += f"Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
            
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            data = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            
            async with aiohttp.ClientSession() as session:
                await session.post(url, json=data)
        except Exception as e:
            log.error(f"Error sending Telegram alert: {e}")


class LogAnalyzer:
    """Analyzes logs for patterns and issues"""
    
    def __init__(self):
        self.log_patterns = {
            "error_patterns": [
                r"ERROR.*",
                r"CRITICAL.*",
                r"Exception.*",
                r"Traceback.*"
            ],
            "security_patterns": [
                r"Invalid API key",
                r"Unauthorized access",
                r"Rate limit exceeded",
                r"Suspicious activity"
            ],
            "performance_patterns": [
                r"Slow query",
                r"Timeout",
                r"Connection pool exhausted"
            ]
        }
    
    async def analyze_recent_logs(self, log_file: str) -> Dict[str, Any]:
        """Analyze recent logs for issues"""
        try:
            # Read last 1000 lines of log file
            with open(log_file, 'r') as f:
                lines = f.readlines()[-1000:]
            
            analysis = {
                "error_count": 0,
                "security_events": 0,
                "performance_issues": 0,
                "recent_errors": []
            }
            
            for line in lines:
                # Count errors
                if any(pattern in line for pattern in ["ERROR", "CRITICAL", "Exception"]):
                    analysis["error_count"] += 1
                    if len(analysis["recent_errors"]) < 10:
                        analysis["recent_errors"].append(line.strip())
                
                # Count security events
                if any(pattern in line for pattern in ["Invalid API key", "Unauthorized", "Rate limit"]):
                    analysis["security_events"] += 1
                
                # Count performance issues
                if any(pattern in line for pattern in ["Slow query", "Timeout", "Connection pool"]):
                    analysis["performance_issues"] += 1
            
            return analysis
        except Exception as e:
            log.error(f"Error analyzing logs: {e}")
            return {}


class MonitoringService:
    """Main monitoring service"""
    
    def __init__(self):
        self.metrics_collector = MetricsCollector()
        self.alert_manager = AlertManager()
        self.log_analyzer = LogAnalyzer()
        self.db_connection = None
        self.running = False
    
    async def initialize(self):
        """Initialize monitoring service"""
        try:
            # Connect to database
            database_url = os.getenv("DATABASE_URL", "")
            if database_url:
                self.db_connection = await asyncpg.connect(database_url)
                log.success("[Monitoring] Connected to database")
            
            # Create monitoring tables if they don't exist
            await self._create_monitoring_tables()
            
            log.success("[Monitoring] Service initialized")
        except Exception as e:
            log.error(f"[Monitoring] Initialization failed: {e}")
            raise
    
    async def _create_monitoring_tables(self):
        """Create monitoring tables"""
        if not self.db_connection:
            return
        
        await self.db_connection.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_metrics (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                component VARCHAR(50) NOT NULL,
                metrics JSONB NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS monitoring_alerts (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                level VARCHAR(20) NOT NULL,
                component VARCHAR(50) NOT NULL,
                message TEXT NOT NULL,
                metadata JSONB DEFAULT '{}'::jsonb,
                resolved BOOLEAN DEFAULT FALSE
            );
            
            CREATE INDEX idx_monitoring_metrics_timestamp ON monitoring_metrics(timestamp DESC);
            CREATE INDEX idx_monitoring_alerts_timestamp ON monitoring_alerts(timestamp DESC);
            CREATE INDEX idx_monitoring_alerts_resolved ON monitoring_alerts(resolved);
        """)
    
    async def collect_and_store_metrics(self):
        """Collect and store metrics"""
        try:
            # Collect system metrics
            system_metrics = await self.metrics_collector.collect_system_metrics()
            if system_metrics and self.db_connection:
                await self.db_connection.execute("""
                    INSERT INTO monitoring_metrics (component, metrics)
                    VALUES ('system', $1)
                """, json.dumps(system_metrics))
            
            # Collect application metrics
            if self.db_connection:
                app_metrics = await self.metrics_collector.collect_application_metrics(self.db_connection)
                if app_metrics:
                    await self.db_connection.execute("""
                        INSERT INTO monitoring_metrics (component, metrics)
                        VALUES ('application', $1)
                    """, json.dumps(app_metrics))
            
            # Combine metrics for alert checking
            combined_metrics = {**system_metrics, **app_metrics}
            
            # Check for alerts
            alerts = await self.alert_manager.check_alerts(combined_metrics)
            if alerts:
                await self.alert_manager.send_notifications(alerts)
                
                # Store alerts in database
                for alert in alerts:
                    await self.db_connection.execute("""
                        INSERT INTO monitoring_alerts (level, component, message, metadata)
                        VALUES ($1, $2, $3, $4)
                    """, alert.level.value, alert.component, alert.message, json.dumps(alert.metadata or {}))
            
            log.info(f"[Monitoring] Collected metrics and processed {len(alerts)} alerts")
        
        except Exception as e:
            log.error(f"[Monitoring] Error collecting metrics: {e}")
    
    async def cleanup_old_data(self):
        """Clean up old monitoring data"""
        if not self.db_connection:
            return
        
        try:
            # Keep metrics for 7 days
            await self.db_connection.execute("""
                DELETE FROM monitoring_metrics 
                WHERE timestamp < NOW() - INTERVAL '7 days'
            """)
            
            # Keep resolved alerts for 30 days
            await self.db_connection.execute("""
                DELETE FROM monitoring_alerts 
                WHERE resolved = TRUE 
                AND timestamp < NOW() - INTERVAL '30 days'
            """)
            
            log.info("[Monitoring] Cleaned up old monitoring data")
        except Exception as e:
            log.error(f"[Monitoring] Error cleaning up data: {e}")
    
    async def run(self):
        """Run monitoring service"""
        self.running = True
        log.info("[Monitoring] Starting monitoring service")
        
        while self.running:
            try:
                # Collect metrics every 60 seconds
                await self.collect_and_store_metrics()
                
                # Cleanup old data every hour
                if datetime.now().minute == 0:
                    await self.cleanup_old_data()
                
                # Wait for next cycle
                await asyncio.sleep(60)
            
            except KeyboardInterrupt:
                log.info("[Monitoring] Received shutdown signal")
                break
            except Exception as e:
                log.error(f"[Monitoring] Error in main loop: {e}")
                await asyncio.sleep(60)
    
    async def shutdown(self):
        """Shutdown monitoring service"""
        self.running = False
        if self.db_connection:
            await self.db_connection.close()
        log.info("[Monitoring] Service shutdown complete")


async def main():
    """Main function"""
    monitoring_service = MonitoringService()
    
    try:
        await monitoring_service.initialize()
        await monitoring_service.run()
    except Exception as e:
        log.error(f"[Monitoring] Fatal error: {e}")
    finally:
        await monitoring_service.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
