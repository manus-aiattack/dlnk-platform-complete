"""
Resource Monitor for dLNk Attack Platform
Monitors CPU, Memory, Disk, and Network resources
"""

import asyncio
import psutil
import time
from typing import Dict, List, Optional, Callable
from collections import deque
from datetime import datetime
import logging

log = logging.getLogger(__name__)


class ResourceMonitor:
    """
    System Resource Monitor
    
    Features:
    - Monitor CPU usage
    - Monitor memory usage
    - Monitor disk usage
    - Monitor network I/O
    - Track resource trends
    - Alert on resource exhaustion
    - Trigger resource optimization
    """
    
    def __init__(self, history_size: int = 300):
        self.history_size = history_size
        self.monitoring = False
        self.check_interval = 5  # seconds
        
        # Resource history
        self.cpu_history = deque(maxlen=history_size)
        self.memory_history = deque(maxlen=history_size)
        self.disk_history = deque(maxlen=history_size)
        self.network_history = deque(maxlen=history_size)
        
        # Thresholds
        self.thresholds = {
            'cpu_percent': 90.0,
            'memory_percent': 85.0,
            'disk_percent': 90.0,
            'swap_percent': 50.0
        }
        
        # Alert callbacks
        self.alert_callbacks = []
        
        # Optimization callbacks
        self.optimization_callbacks = {}
        
        # Network baseline
        self.network_baseline = None
    
    async def start_monitoring(self):
        """Start resource monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        log.info("[ResourceMonitor] Started resource monitoring")
        
        # Initialize network baseline
        self.network_baseline = psutil.net_io_counters()
        
        # Start monitoring loop
        asyncio.create_task(self._monitoring_loop())
    
    async def stop_monitoring(self):
        """Stop resource monitoring"""
        self.monitoring = False
        log.info("[ResourceMonitor] Stopped resource monitoring")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                await self._collect_metrics()
                await self._check_thresholds()
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                log.error(f"[ResourceMonitor] Monitoring error: {e}")
                await asyncio.sleep(self.check_interval)
    
    async def _collect_metrics(self):
        """Collect current resource metrics"""
        timestamp = time.time()
        
        # CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        self.cpu_history.append({
            'timestamp': timestamp,
            'percent': cpu_percent,
            'count': cpu_count,
            'freq_current': cpu_freq.current if cpu_freq else 0,
            'freq_max': cpu_freq.max if cpu_freq else 0
        })
        
        # Memory
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        self.memory_history.append({
            'timestamp': timestamp,
            'total': memory.total,
            'available': memory.available,
            'used': memory.used,
            'percent': memory.percent,
            'swap_total': swap.total,
            'swap_used': swap.used,
            'swap_percent': swap.percent
        })
        
        # Disk
        disk = psutil.disk_usage('/')
        disk_io = psutil.disk_io_counters()
        
        self.disk_history.append({
            'timestamp': timestamp,
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': disk.percent,
            'read_bytes': disk_io.read_bytes if disk_io else 0,
            'write_bytes': disk_io.write_bytes if disk_io else 0
        })
        
        # Network
        net_io = psutil.net_io_counters()
        
        if self.network_baseline:
            bytes_sent = net_io.bytes_sent - self.network_baseline.bytes_sent
            bytes_recv = net_io.bytes_recv - self.network_baseline.bytes_recv
        else:
            bytes_sent = 0
            bytes_recv = 0
        
        self.network_history.append({
            'timestamp': timestamp,
            'bytes_sent': bytes_sent,
            'bytes_recv': bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        })
    
    async def _check_thresholds(self):
        """Check if any thresholds are exceeded"""
        if not self.cpu_history or not self.memory_history or not self.disk_history:
            return
        
        # Get latest metrics
        cpu = self.cpu_history[-1]
        memory = self.memory_history[-1]
        disk = self.disk_history[-1]
        
        # Check CPU
        if cpu['percent'] > self.thresholds['cpu_percent']:
            await self._trigger_alert('cpu', cpu['percent'], self.thresholds['cpu_percent'])
            await self._trigger_optimization('cpu')
        
        # Check Memory
        if memory['percent'] > self.thresholds['memory_percent']:
            await self._trigger_alert('memory', memory['percent'], self.thresholds['memory_percent'])
            await self._trigger_optimization('memory')
        
        # Check Disk
        if disk['percent'] > self.thresholds['disk_percent']:
            await self._trigger_alert('disk', disk['percent'], self.thresholds['disk_percent'])
            await self._trigger_optimization('disk')
        
        # Check Swap
        if memory['swap_percent'] > self.thresholds['swap_percent']:
            await self._trigger_alert('swap', memory['swap_percent'], self.thresholds['swap_percent'])
    
    async def _trigger_alert(self, resource: str, current: float, threshold: float):
        """Trigger alert for resource threshold exceeded"""
        alert = {
            'resource': resource,
            'current': current,
            'threshold': threshold,
            'timestamp': datetime.now(),
            'severity': self._calculate_severity(current, threshold)
        }
        
        log.warning(
            f"[ResourceMonitor] {resource.upper()} threshold exceeded: "
            f"{current:.1f}% > {threshold:.1f}% (severity: {alert['severity']})"
        )
        
        # Call alert callbacks
        for callback in self.alert_callbacks:
            try:
                await callback(alert)
            except Exception as e:
                log.error(f"[ResourceMonitor] Alert callback error: {e}")
    
    def _calculate_severity(self, current: float, threshold: float) -> str:
        """Calculate severity of resource issue"""
        if current >= threshold * 1.2:
            return 'CRITICAL'
        elif current >= threshold * 1.1:
            return 'HIGH'
        elif current >= threshold:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    async def _trigger_optimization(self, resource: str):
        """Trigger optimization for resource"""
        if resource in self.optimization_callbacks:
            log.info(f"[ResourceMonitor] Triggering {resource} optimization")
            try:
                callback = self.optimization_callbacks[resource]
                await callback()
            except Exception as e:
                log.error(f"[ResourceMonitor] Optimization callback error: {e}")
    
    def register_alert_callback(self, callback: Callable):
        """Register callback for resource alerts"""
        self.alert_callbacks.append(callback)
        log.info("[ResourceMonitor] Registered alert callback")
    
    def register_optimization_callback(self, resource: str, callback: Callable):
        """Register callback for resource optimization"""
        self.optimization_callbacks[resource] = callback
        log.info(f"[ResourceMonitor] Registered optimization callback for {resource}")
    
    def set_threshold(self, resource: str, threshold: float):
        """Set threshold for resource"""
        if resource in self.thresholds:
            self.thresholds[resource] = threshold
            log.info(f"[ResourceMonitor] Set {resource} threshold to {threshold}%")
    
    def get_current_metrics(self) -> Dict:
        """Get current resource metrics"""
        if not self.cpu_history or not self.memory_history or not self.disk_history:
            return {'error': 'No data available'}
        
        cpu = self.cpu_history[-1]
        memory = self.memory_history[-1]
        disk = self.disk_history[-1]
        network = self.network_history[-1] if self.network_history else {}
        
        return {
            'cpu': {
                'percent': cpu['percent'],
                'count': cpu['count'],
                'freq_current': cpu['freq_current'],
                'status': 'OK' if cpu['percent'] < self.thresholds['cpu_percent'] else 'WARNING'
            },
            'memory': {
                'total_gb': memory['total'] / (1024**3),
                'used_gb': memory['used'] / (1024**3),
                'available_gb': memory['available'] / (1024**3),
                'percent': memory['percent'],
                'swap_percent': memory['swap_percent'],
                'status': 'OK' if memory['percent'] < self.thresholds['memory_percent'] else 'WARNING'
            },
            'disk': {
                'total_gb': disk['total'] / (1024**3),
                'used_gb': disk['used'] / (1024**3),
                'free_gb': disk['free'] / (1024**3),
                'percent': disk['percent'],
                'status': 'OK' if disk['percent'] < self.thresholds['disk_percent'] else 'WARNING'
            },
            'network': {
                'bytes_sent_mb': network.get('bytes_sent', 0) / (1024**2),
                'bytes_recv_mb': network.get('bytes_recv', 0) / (1024**2),
                'packets_sent': network.get('packets_sent', 0),
                'packets_recv': network.get('packets_recv', 0)
            }
        }
    
    def get_statistics(self, resource: str = 'all') -> Dict:
        """Get resource statistics"""
        stats = {}
        
        if resource in ['cpu', 'all']:
            if self.cpu_history:
                cpu_values = [m['percent'] for m in self.cpu_history]
                stats['cpu'] = {
                    'current': cpu_values[-1],
                    'average': sum(cpu_values) / len(cpu_values),
                    'max': max(cpu_values),
                    'min': min(cpu_values)
                }
        
        if resource in ['memory', 'all']:
            if self.memory_history:
                mem_values = [m['percent'] for m in self.memory_history]
                stats['memory'] = {
                    'current': mem_values[-1],
                    'average': sum(mem_values) / len(mem_values),
                    'max': max(mem_values),
                    'min': min(mem_values)
                }
        
        if resource in ['disk', 'all']:
            if self.disk_history:
                disk_values = [m['percent'] for m in self.disk_history]
                stats['disk'] = {
                    'current': disk_values[-1],
                    'average': sum(disk_values) / len(disk_values),
                    'max': max(disk_values),
                    'min': min(disk_values)
                }
        
        return stats
    
    def get_trends(self, resource: str, window: int = 60) -> Dict:
        """
        Analyze resource trends
        
        Args:
            resource: Resource to analyze (cpu, memory, disk)
            window: Number of data points to analyze
        
        Returns:
            Trend analysis
        """
        if resource == 'cpu':
            history = self.cpu_history
            key = 'percent'
        elif resource == 'memory':
            history = self.memory_history
            key = 'percent'
        elif resource == 'disk':
            history = self.disk_history
            key = 'percent'
        else:
            return {'error': f'Unknown resource: {resource}'}
        
        if len(history) < 2:
            return {'error': 'Insufficient data'}
        
        # Get recent values
        recent = list(history)[-window:]
        values = [m[key] for m in recent]
        
        # Calculate trend
        if len(values) >= 2:
            first_half = values[:len(values)//2]
            second_half = values[len(values)//2:]
            
            first_avg = sum(first_half) / len(first_half)
            second_avg = sum(second_half) / len(second_half)
            
            change = second_avg - first_avg
            change_percent = (change / first_avg * 100) if first_avg > 0 else 0
            
            if change_percent > 10:
                trend = 'increasing'
            elif change_percent < -10:
                trend = 'decreasing'
            else:
                trend = 'stable'
        else:
            trend = 'unknown'
            change_percent = 0
        
        return {
            'resource': resource,
            'trend': trend,
            'change_percent': change_percent,
            'current': values[-1],
            'average': sum(values) / len(values),
            'data_points': len(values)
        }
    
    def get_process_info(self, top_n: int = 10) -> List[Dict]:
        """Get information about top resource-consuming processes"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                processes.append({
                    'pid': info['pid'],
                    'name': info['name'],
                    'cpu_percent': info['cpu_percent'],
                    'memory_percent': info['memory_percent']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        
        return processes[:top_n]


if __name__ == '__main__':
    async def test():
        """Test resource monitor"""
        monitor = ResourceMonitor()
        
        # Register alert callback
        async def alert_handler(alert):
            print(f"\n[!] ALERT: {alert['resource']} at {alert['current']:.1f}% (threshold: {alert['threshold']:.1f}%)")
        
        monitor.register_alert_callback(alert_handler)
        
        # Start monitoring
        await monitor.start_monitoring()
        
        # Wait for some data
        await asyncio.sleep(10)
        
        # Get current metrics
        metrics = monitor.get_current_metrics()
        print("\n[+] Current Metrics:")
        print(f"  CPU: {metrics['cpu']['percent']:.1f}% ({metrics['cpu']['status']})")
        print(f"  Memory: {metrics['memory']['percent']:.1f}% ({metrics['memory']['status']})")
        print(f"  Disk: {metrics['disk']['percent']:.1f}% ({metrics['disk']['status']})")
        
        # Get statistics
        stats = monitor.get_statistics()
        print("\n[+] Statistics:")
        for resource, data in stats.items():
            print(f"  {resource}: avg={data['average']:.1f}%, max={data['max']:.1f}%")
        
        # Get trends
        for resource in ['cpu', 'memory', 'disk']:
            trend = monitor.get_trends(resource)
            print(f"\n[+] {resource.upper()} Trend: {trend['trend']} ({trend['change_percent']:+.1f}%)")
        
        # Get top processes
        processes = monitor.get_process_info(top_n=5)
        print("\n[+] Top Processes:")
        for proc in processes:
            print(f"  {proc['name']}: CPU={proc['cpu_percent']:.1f}%, MEM={proc['memory_percent']:.1f}%")
        
        await monitor.stop_monitoring()
    
    asyncio.run(test())

