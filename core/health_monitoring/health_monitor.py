"""
Health Monitor using psutil
"""

import asyncio
import psutil
from typing import Dict
import logging

log = logging.getLogger(__name__)


class HealthMonitor:
    """System health monitoring"""
    
    def __init__(self):
        self.health_history = []
        self.alert_thresholds = {
            'cpu_percent': 90.0,
            'memory_percent': 85.0,
            'disk_percent': 90.0
        }
    
    async def check_health(self) -> Dict:
        """Check system health"""
        
        health = {
            'cpu': await self.check_cpu(),
            'memory': await self.check_memory(),
            'disk': await self.check_disk(),
            'network': await self.check_network(),
            'processes': await self.check_processes()
        }
        
        # Determine overall status
        health['status'] = self._determine_status(health)
        
        # Store history
        self.health_history.append(health)
        if len(self.health_history) > 100:
            self.health_history.pop(0)
        
        return health
    
    async def check_cpu(self) -> Dict:
        """Check CPU usage"""
        
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        
        return {
            'percent': cpu_percent,
            'count': cpu_count,
            'per_cpu': psutil.cpu_percent(interval=0.1, percpu=True),
            'status': 'CRITICAL' if cpu_percent > 90 else 'WARNING' if cpu_percent > 75 else 'OK'
        }
    
    async def check_memory(self) -> Dict:
        """Check memory usage"""
        
        memory = psutil.virtual_memory()
        
        return {
            'total': memory.total,
            'available': memory.available,
            'percent': memory.percent,
            'used': memory.used,
            'free': memory.free,
            'status': 'CRITICAL' if memory.percent > 85 else 'WARNING' if memory.percent > 70 else 'OK'
        }
    
    async def check_disk(self) -> Dict:
        """Check disk usage"""
        
        disk = psutil.disk_usage('/')
        
        return {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': disk.percent,
            'status': 'CRITICAL' if disk.percent > 90 else 'WARNING' if disk.percent > 75 else 'OK'
        }
    
    async def check_network(self) -> Dict:
        """Check network statistics"""
        
        net_io = psutil.net_io_counters()
        
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout
        }
    
    async def check_processes(self) -> Dict:
        """Check process information"""
        
        process_count = len(psutil.pids())
        
        # Get top processes by CPU
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage
        top_processes = sorted(processes, key=lambda x: x.get('cpu_percent', 0), reverse=True)[:5]
        
        return {
            'total': process_count,
            'top_cpu': top_processes
        }
    
    def _determine_status(self, health: Dict) -> str:
        """Determine overall health status"""
        
        statuses = [
            health['cpu']['status'],
            health['memory']['status'],
            health['disk']['status']
        ]
        
        if 'CRITICAL' in statuses:
            return 'CRITICAL'
        elif 'WARNING' in statuses:
            return 'WARNING'
        else:
            return 'OK'
