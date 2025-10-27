"""
System Service for dLNk Attack Platform
System monitoring and management
"""

import asyncio
import psutil
import platform
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class SystemStatus:
    """System status data model"""
    status: str  # healthy, degraded, unhealthy
    version: str
    uptime: float
    timestamp: str


@dataclass
class ResourceUsage:
    """Resource usage data model"""
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_total_mb: float
    disk_percent: float
    disk_used_gb: float
    disk_total_gb: float
    network_sent_mb: float
    network_recv_mb: float


@dataclass
class LogEntry:
    """Log entry data model"""
    id: str
    timestamp: str
    level: str
    source: str
    message: str
    metadata: Dict[str, Any]


class SystemService:
    """
    System Service
    
    Monitors system health and resources
    """
    
    def __init__(self, version: str, database_service, attack_service):
        """
        Initialize System Service
        
        Args:
            version: Application version
            database_service: Database service instance
            attack_service: Attack service instance
        """
        self.version = version
        self.db = database_service
        self.attack_service = attack_service
        self.start_time = datetime.utcnow()
        self.initial_net_io = psutil.net_io_counters()
    
    async def get_system_status(self) -> SystemStatus:
        """
        Get system status
        
        Returns:
            SystemStatus object
        """
        # Check system health
        status = "healthy"
        
        try:
            # Check CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                status = "degraded"
            
            # Check memory
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                status = "degraded"
            
            # Check disk
            disk = psutil.disk_usage('/')
            if disk.percent > 90:
                status = "degraded"
            
            # Check database
            db_healthy = await self._check_database_health()
            if not db_healthy:
                status = "unhealthy"
            
        except Exception:
            status = "unhealthy"
        
        uptime = (datetime.utcnow() - self.start_time).total_seconds()
        
        return SystemStatus(
            status=status,
            version=self.version,
            uptime=uptime,
            timestamp=datetime.utcnow().isoformat()
        )
    
    async def get_resource_usage(self) -> ResourceUsage:
        """
        Get resource usage
        
        Returns:
            ResourceUsage object
        """
        # CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory
        memory = psutil.virtual_memory()
        memory_used_mb = memory.used / (1024 * 1024)
        memory_total_mb = memory.total / (1024 * 1024)
        
        # Disk
        disk = psutil.disk_usage('/')
        disk_used_gb = disk.used / (1024 * 1024 * 1024)
        disk_total_gb = disk.total / (1024 * 1024 * 1024)
        
        # Network
        net_io = psutil.net_io_counters()
        network_sent_mb = (net_io.bytes_sent - self.initial_net_io.bytes_sent) / (1024 * 1024)
        network_recv_mb = (net_io.bytes_recv - self.initial_net_io.bytes_recv) / (1024 * 1024)
        
        return ResourceUsage(
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            memory_used_mb=memory_used_mb,
            memory_total_mb=memory_total_mb,
            disk_percent=disk.percent,
            disk_used_gb=disk_used_gb,
            disk_total_gb=disk_total_gb,
            network_sent_mb=network_sent_mb,
            network_recv_mb=network_recv_mb
        )
    
    async def get_active_attacks(self) -> List[Dict[str, Any]]:
        """
        Get list of active attacks
        
        Returns:
            List of active attack dictionaries
        """
        attacks = await self.attack_service.list_attacks(status="running")
        return [asdict(attack) for attack in attacks]
    
    async def get_system_logs(
        self,
        level: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[LogEntry]:
        """
        Get system logs
        
        Args:
            level: Filter by log level
            source: Filter by source
            limit: Maximum number of results
            offset: Offset for pagination
            
        Returns:
            List of LogEntry objects
        """
        filters = {}
        if level:
            filters["level"] = level
        if source:
            filters["source"] = source
        
        logs_data = await self.db.get_logs(filters, limit, offset)
        return [LogEntry(**data) for data in logs_data]
    
    async def log_event(
        self,
        level: str,
        source: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log an event
        
        Args:
            level: Log level (debug, info, warning, error, critical)
            source: Event source
            message: Log message
            metadata: Additional metadata
        """
        import uuid
        
        log_entry = LogEntry(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow().isoformat(),
            level=level,
            source=source,
            message=message,
            metadata=metadata or {}
        )
        
        await self.db.save_log(asdict(log_entry))
    
    async def get_system_info(self) -> Dict[str, Any]:
        """
        Get detailed system information
        
        Returns:
            Dictionary with system information
        """
        return {
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor()
            },
            "python": {
                "version": platform.python_version(),
                "implementation": platform.python_implementation()
            },
            "cpu": {
                "count": psutil.cpu_count(),
                "physical_count": psutil.cpu_count(logical=False),
                "percent": psutil.cpu_percent(interval=1)
            },
            "memory": {
                "total_gb": psutil.virtual_memory().total / (1024 ** 3),
                "available_gb": psutil.virtual_memory().available / (1024 ** 3),
                "percent": psutil.virtual_memory().percent
            },
            "disk": {
                "total_gb": psutil.disk_usage('/').total / (1024 ** 3),
                "used_gb": psutil.disk_usage('/').used / (1024 ** 3),
                "free_gb": psutil.disk_usage('/').free / (1024 ** 3),
                "percent": psutil.disk_usage('/').percent
            },
            "application": {
                "version": self.version,
                "uptime_seconds": (datetime.utcnow() - self.start_time).total_seconds(),
                "start_time": self.start_time.isoformat()
            }
        }
    
    async def _check_database_health(self) -> bool:
        """
        Check database health
        
        Returns:
            True if database is healthy
        """
        try:
            # Try a simple query
            await self.db.health_check()
            return True
        except Exception:
            return False
    
    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get system statistics
        
        Returns:
            Dictionary with statistics
        """
        # Get attack statistics
        total_attacks = await self.db.count_attacks()
        completed_attacks = await self.db.count_attacks(status="completed")
        failed_attacks = await self.db.count_attacks(status="failed")
        active_attacks = await self.attack_service.get_active_attacks_count()
        
        # Get vulnerability statistics
        total_vulnerabilities = await self.db.count_vulnerabilities()
        critical_vulnerabilities = await self.db.count_vulnerabilities(severity="critical")
        high_vulnerabilities = await self.db.count_vulnerabilities(severity="high")
        
        # Get user statistics
        total_users = await self.db.count_users()
        admin_users = await self.db.count_users(role="admin")
        
        return {
            "attacks": {
                "total": total_attacks,
                "completed": completed_attacks,
                "failed": failed_attacks,
                "active": active_attacks,
                "success_rate": (completed_attacks / total_attacks * 100) if total_attacks > 0 else 0
            },
            "vulnerabilities": {
                "total": total_vulnerabilities,
                "critical": critical_vulnerabilities,
                "high": high_vulnerabilities
            },
            "users": {
                "total": total_users,
                "admins": admin_users
            }
        }
    
    async def cleanup_old_data(self, days: int = 30) -> Dict[str, int]:
        """
        Cleanup old data
        
        Args:
            days: Delete data older than this many days
            
        Returns:
            Dictionary with cleanup counts
        """
        from datetime import timedelta
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Cleanup old attacks
        deleted_attacks = await self.db.delete_old_attacks(cutoff_date)
        
        # Cleanup old logs
        deleted_logs = await self.db.delete_old_logs(cutoff_date)
        
        # Cleanup old reports
        deleted_reports = await self.db.delete_old_reports(cutoff_date)
        
        return {
            "attacks": deleted_attacks,
            "logs": deleted_logs,
            "reports": deleted_reports
        }

