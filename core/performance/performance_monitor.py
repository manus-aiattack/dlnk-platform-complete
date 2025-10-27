"""
Performance Monitoring and Optimization System
"""

import asyncio
import time
import psutil
from typing import Dict, List, Optional, Callable
from datetime import datetime
from collections import deque
import logging

log = logging.getLogger(__name__)


class PerformanceMonitor:
    """
    Performance Monitoring System
    
    Features:
    - Real-time performance tracking
    - Resource usage monitoring
    - Bottleneck detection
    - Automatic optimization
    """
    
    def __init__(self):
        self.metrics = {
            'cpu_usage': deque(maxlen=100),
            'memory_usage': deque(maxlen=100),
            'response_times': deque(maxlen=1000),
            'request_count': 0,
            'error_count': 0
        }
        
        self.thresholds = {
            'cpu_usage': 80.0,  # %
            'memory_usage': 80.0,  # %
            'response_time': 5.0,  # seconds
            'error_rate': 0.05  # 5%
        }
        
        self.monitoring_active = False
    
    async def start_monitoring(self):
        """Start performance monitoring"""
        
        log.info("[PerformanceMonitor] Starting monitoring...")
        
        self.monitoring_active = True
        
        # Start monitoring task
        asyncio.create_task(self._monitor_loop())
    
    async def stop_monitoring(self):
        """Stop performance monitoring"""
        
        log.info("[PerformanceMonitor] Stopping monitoring...")
        
        self.monitoring_active = False
    
    async def _monitor_loop(self):
        """Main monitoring loop"""
        
        while self.monitoring_active:
            try:
                # Collect metrics
                await self._collect_metrics()
                
                # Check thresholds
                await self._check_thresholds()
                
                # Wait before next collection
                await asyncio.sleep(1)
                
            except Exception as e:
                log.error(f"[PerformanceMonitor] Monitoring error: {e}")
    
    async def _collect_metrics(self):
        """Collect performance metrics"""
        
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        self.metrics['cpu_usage'].append({
            'timestamp': datetime.now().isoformat(),
            'value': cpu_percent
        })
        
        # Memory usage
        memory = psutil.virtual_memory()
        self.metrics['memory_usage'].append({
            'timestamp': datetime.now().isoformat(),
            'value': memory.percent
        })
    
    async def _check_thresholds(self):
        """Check if metrics exceed thresholds"""
        
        # Check CPU
        if self.metrics['cpu_usage']:
            recent_cpu = [m['value'] for m in list(self.metrics['cpu_usage'])[-10:]]
            avg_cpu = sum(recent_cpu) / len(recent_cpu)
            
            if avg_cpu > self.thresholds['cpu_usage']:
                log.warning(f"[PerformanceMonitor] High CPU usage: {avg_cpu:.1f}%")
                await self._optimize_cpu_usage()
        
        # Check memory
        if self.metrics['memory_usage']:
            recent_memory = [m['value'] for m in list(self.metrics['memory_usage'])[-10:]]
            avg_memory = sum(recent_memory) / len(recent_memory)
            
            if avg_memory > self.thresholds['memory_usage']:
                log.warning(f"[PerformanceMonitor] High memory usage: {avg_memory:.1f}%")
                await self._optimize_memory_usage()
        
        # Check error rate
        if self.metrics['request_count'] > 0:
            error_rate = self.metrics['error_count'] / self.metrics['request_count']
            
            if error_rate > self.thresholds['error_rate']:
                log.warning(f"[PerformanceMonitor] High error rate: {error_rate:.1%}")
    
    async def _optimize_cpu_usage(self):
        """Optimize CPU usage"""
        
        log.info("[PerformanceMonitor] Optimizing CPU usage...")
        
        # Reduce parallelism
        # Implement actual optimization logic
        
    async def _optimize_memory_usage(self):
        """Optimize memory usage"""
        
        log.info("[PerformanceMonitor] Optimizing memory usage...")
        
        # Clear caches
        # Implement actual optimization logic
    
    async def track_operation(
        self,
        operation: Callable,
        *args,
        **kwargs
    ) -> Dict:
        """
        Track operation performance
        
        Args:
            operation: Operation to track
            *args: Operation arguments
            **kwargs: Operation keyword arguments
        
        Returns:
            Operation result with performance metrics
        """
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss
        
        self.metrics['request_count'] += 1
        
        try:
            result = await operation(*args, **kwargs)
            
            execution_time = time.time() - start_time
            memory_used = psutil.Process().memory_info().rss - start_memory
            
            # Record metrics
            self.metrics['response_times'].append({
                'timestamp': datetime.now().isoformat(),
                'value': execution_time,
                'operation': operation.__name__
            })
            
            # Check if slow
            if execution_time > self.thresholds['response_time']:
                log.warning(f"[PerformanceMonitor] Slow operation: {operation.__name__} took {execution_time:.2f}s")
            
            return {
                'success': True,
                'result': result,
                'performance': {
                    'execution_time': execution_time,
                    'memory_used': memory_used,
                    'timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            self.metrics['error_count'] += 1
            
            execution_time = time.time() - start_time
            
            return {
                'success': False,
                'error': str(e),
                'performance': {
                    'execution_time': execution_time,
                    'timestamp': datetime.now().isoformat()
                }
            }
    
    async def get_statistics(self) -> Dict:
        """Get performance statistics"""
        
        stats = {
            'current_cpu': psutil.cpu_percent(),
            'current_memory': psutil.virtual_memory().percent,
            'total_requests': self.metrics['request_count'],
            'total_errors': self.metrics['error_count'],
            'error_rate': self.metrics['error_count'] / self.metrics['request_count'] if self.metrics['request_count'] > 0 else 0
        }
        
        # Calculate average response time
        if self.metrics['response_times']:
            response_times = [m['value'] for m in self.metrics['response_times']]
            stats['avg_response_time'] = sum(response_times) / len(response_times)
            stats['min_response_time'] = min(response_times)
            stats['max_response_time'] = max(response_times)
        
        return stats
    
    async def generate_report(self) -> str:
        """Generate performance report"""
        
        stats = await self.get_statistics()
        
        report = []
        report.append("=" * 80)
        report.append("PERFORMANCE REPORT")
        report.append("=" * 80)
        report.append("")
        
        report.append(f"Current CPU Usage: {stats['current_cpu']:.1f}%")
        report.append(f"Current Memory Usage: {stats['current_memory']:.1f}%")
        report.append("")
        
        report.append(f"Total Requests: {stats['total_requests']}")
        report.append(f"Total Errors: {stats['total_errors']}")
        report.append(f"Error Rate: {stats['error_rate']:.2%}")
        report.append("")
        
        if 'avg_response_time' in stats:
            report.append(f"Average Response Time: {stats['avg_response_time']:.3f}s")
            report.append(f"Min Response Time: {stats['min_response_time']:.3f}s")
            report.append(f"Max Response Time: {stats['max_response_time']:.3f}s")
        
        report.append("")
        report.append("=" * 80)
        
        return '\n'.join(report)


if __name__ == '__main__':
    async def test():
        monitor = PerformanceMonitor()
        
        await monitor.start_monitoring()
        
        # Test tracking
        async def test_operation():
            await asyncio.sleep(0.1)
            return "success"
        
        result = await monitor.track_operation(test_operation)
        
        print("Operation Result:")
        print(f"  Success: {result['success']}")
        print(f"  Execution Time: {result['performance']['execution_time']:.3f}s")
        
        # Get statistics
        stats = await monitor.get_statistics()
        
        print("\nPerformance Statistics:")
        print(f"  CPU: {stats['current_cpu']:.1f}%")
        print(f"  Memory: {stats['current_memory']:.1f}%")
        print(f"  Requests: {stats['total_requests']}")
        
        await monitor.stop_monitoring()
    
    asyncio.run(test())

