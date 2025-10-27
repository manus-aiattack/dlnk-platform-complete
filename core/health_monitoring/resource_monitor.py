"""
Resource Monitor
"""

import asyncio
import psutil
from typing import Dict, List
import logging

log = logging.getLogger(__name__)


class ResourceMonitor:
    """Monitors resource usage"""
    
    def __init__(self):
        self.resource_history = []
    
    async def monitor_resources(self) -> Dict:
        """Monitor all resources"""
        
        resources = {
            'cpu': await self.monitor_cpu(),
            'memory': await self.monitor_memory(),
            'disk_io': await self.monitor_disk_io(),
            'network_io': await self.monitor_network_io()
        }
        
        self.resource_history.append(resources)
        if len(self.resource_history) > 1000:
            self.resource_history.pop(0)
        
        return resources
    
    async def monitor_cpu(self) -> Dict:
        """Monitor CPU"""
        
        return {
            'percent': psutil.cpu_percent(interval=0.1),
            'count': psutil.cpu_count(),
            'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
        }
    
    async def monitor_memory(self) -> Dict:
        """Monitor memory"""
        
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            'virtual': vm._asdict(),
            'swap': swap._asdict()
        }
    
    async def monitor_disk_io(self) -> Dict:
        """Monitor disk I/O"""
        
        disk_io = psutil.disk_io_counters()
        
        if disk_io:
            return disk_io._asdict()
        return {}
    
    async def monitor_network_io(self) -> Dict:
        """Monitor network I/O"""
        
        net_io = psutil.net_io_counters()
        
        return net_io._asdict()
    
    async def get_resource_trends(self, window: int = 60) -> Dict:
        """Get resource trends"""
        
        recent = self.resource_history[-window:] if len(self.resource_history) >= window else self.resource_history
        
        if not recent:
            return {}
        
        # Calculate averages
        cpu_avg = sum(r['cpu']['percent'] for r in recent) / len(recent)
        mem_avg = sum(r['memory']['virtual']['percent'] for r in recent) / len(recent)
        
        return {
            'cpu_average': cpu_avg,
            'memory_average': mem_avg,
            'samples': len(recent)
        }
