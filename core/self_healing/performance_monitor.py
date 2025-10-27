"""
Performance Monitor for dLNk Attack Platform
Tracks performance metrics and identifies bottlenecks
"""

import asyncio
import time
import psutil
from typing import Dict, List, Optional
from collections import deque, defaultdict
from datetime import datetime
import statistics
import logging

log = logging.getLogger(__name__)


class PerformanceMonitor:
    """
    Performance Monitoring System
    
    Features:
    - Track API response times
    - Monitor agent execution times
    - Measure database query performance
    - Identify bottlenecks
    - Generate performance reports
    - Trigger optimization when needed
    """
    
    def __init__(self, history_size: int = 1000):
        self.history_size = history_size
        self.metrics = defaultdict(lambda: deque(maxlen=history_size))
        self.thresholds = {}
        self.monitoring = False
        self.start_time = time.time()
        
        # Performance counters
        self.counters = defaultdict(int)
        
        # Bottleneck detection
        self.bottlenecks = []
        
        # Default thresholds (in seconds)
        self.default_thresholds = {
            'api_response': 1.0,
            'database_query': 0.5,
            'agent_execution': 30.0,
            'attack_phase': 300.0
        }
    
    async def start_monitoring(self):
        """Start performance monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.start_time = time.time()
        log.info("[PerfMonitor] Started performance monitoring")
        
        # Start background tasks
        asyncio.create_task(self._periodic_analysis())
    
    async def stop_monitoring(self):
        """Stop performance monitoring"""
        self.monitoring = False
        log.info("[PerfMonitor] Stopped performance monitoring")
    
    def record_metric(
        self,
        metric_name: str,
        value: float,
        metadata: Optional[Dict] = None
    ):
        """
        Record a performance metric
        
        Args:
            metric_name: Name of the metric
            value: Metric value (usually time in seconds)
            metadata: Additional metadata
        """
        metric_data = {
            'value': value,
            'timestamp': time.time(),
            'metadata': metadata or {}
        }
        
        self.metrics[metric_name].append(metric_data)
        self.counters[metric_name] += 1
        
        # Check threshold
        threshold = self.thresholds.get(
            metric_name,
            self.default_thresholds.get(metric_name, float('inf'))
        )
        
        if value > threshold:
            log.warning(
                f"[PerfMonitor] {metric_name} exceeded threshold: "
                f"{value:.3f}s > {threshold:.3f}s"
            )
            self._record_bottleneck(metric_name, value, threshold)
    
    def _record_bottleneck(self, metric_name: str, value: float, threshold: float):
        """Record a performance bottleneck"""
        bottleneck = {
            'metric': metric_name,
            'value': value,
            'threshold': threshold,
            'timestamp': datetime.now(),
            'severity': self._calculate_severity(value, threshold)
        }
        
        self.bottlenecks.append(bottleneck)
        
        # Keep only recent bottlenecks
        if len(self.bottlenecks) > 100:
            self.bottlenecks = self.bottlenecks[-100:]
    
    def _calculate_severity(self, value: float, threshold: float) -> str:
        """Calculate severity of performance issue"""
        ratio = value / threshold
        
        if ratio >= 3.0:
            return 'CRITICAL'
        elif ratio >= 2.0:
            return 'HIGH'
        elif ratio >= 1.5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    async def _periodic_analysis(self):
        """Periodically analyze performance and detect issues"""
        while self.monitoring:
            try:
                await asyncio.sleep(60)  # Analyze every minute
                await self._analyze_performance()
            except Exception as e:
                log.error(f"[PerfMonitor] Analysis error: {e}")
    
    async def _analyze_performance(self):
        """Analyze current performance metrics"""
        log.debug("[PerfMonitor] Analyzing performance...")
        
        for metric_name, data_points in self.metrics.items():
            if len(data_points) < 10:
                continue
            
            values = [d['value'] for d in data_points]
            
            # Calculate statistics
            avg = statistics.mean(values)
            median = statistics.median(values)
            
            # Check for degradation
            recent_values = values[-10:]
            recent_avg = statistics.mean(recent_values)
            
            if recent_avg > avg * 1.5:
                log.warning(
                    f"[PerfMonitor] Performance degradation detected in {metric_name}: "
                    f"recent avg {recent_avg:.3f}s vs overall avg {avg:.3f}s"
                )
    
    def get_statistics(self, metric_name: Optional[str] = None) -> Dict:
        """
        Get performance statistics
        
        Args:
            metric_name: Specific metric, or None for all
        
        Returns:
            Performance statistics
        """
        if metric_name:
            return self._calculate_metric_stats(metric_name)
        else:
            return {
                name: self._calculate_metric_stats(name)
                for name in self.metrics.keys()
            }
    
    def _calculate_metric_stats(self, metric_name: str) -> Dict:
        """Calculate statistics for a specific metric"""
        if metric_name not in self.metrics or len(self.metrics[metric_name]) == 0:
            return {
                'count': 0,
                'error': 'No data available'
            }
        
        values = [d['value'] for d in self.metrics[metric_name]]
        
        stats = {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'mean': statistics.mean(values),
            'median': statistics.median(values)
        }
        
        if len(values) >= 2:
            stats['stdev'] = statistics.stdev(values)
        
        # Percentiles
        sorted_values = sorted(values)
        stats['p50'] = sorted_values[len(sorted_values) // 2]
        stats['p95'] = sorted_values[int(len(sorted_values) * 0.95)]
        stats['p99'] = sorted_values[int(len(sorted_values) * 0.99)]
        
        return stats
    
    def get_bottlenecks(self, severity: Optional[str] = None) -> List[Dict]:
        """
        Get recorded bottlenecks
        
        Args:
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
        
        Returns:
            List of bottlenecks
        """
        if severity:
            return [b for b in self.bottlenecks if b['severity'] == severity]
        return self.bottlenecks
    
    def set_threshold(self, metric_name: str, threshold: float):
        """Set performance threshold for a metric"""
        self.thresholds[metric_name] = threshold
        log.info(f"[PerfMonitor] Set threshold for {metric_name}: {threshold}s")
    
    def get_report(self) -> Dict:
        """Generate comprehensive performance report"""
        uptime = time.time() - self.start_time
        
        report = {
            'uptime_seconds': uptime,
            'total_metrics': len(self.metrics),
            'total_measurements': sum(self.counters.values()),
            'bottlenecks': {
                'total': len(self.bottlenecks),
                'critical': len([b for b in self.bottlenecks if b['severity'] == 'CRITICAL']),
                'high': len([b for b in self.bottlenecks if b['severity'] == 'HIGH']),
                'medium': len([b for b in self.bottlenecks if b['severity'] == 'MEDIUM']),
                'low': len([b for b in self.bottlenecks if b['severity'] == 'LOW'])
            },
            'metrics': {}
        }
        
        # Add statistics for each metric
        for metric_name in self.metrics.keys():
            report['metrics'][metric_name] = self._calculate_metric_stats(metric_name)
        
        return report
    
    def clear_history(self, metric_name: Optional[str] = None):
        """Clear performance history"""
        if metric_name:
            if metric_name in self.metrics:
                self.metrics[metric_name].clear()
                self.counters[metric_name] = 0
                log.info(f"[PerfMonitor] Cleared history for {metric_name}")
        else:
            self.metrics.clear()
            self.counters.clear()
            self.bottlenecks.clear()
            log.info("[PerfMonitor] Cleared all history")


class PerformanceTimer:
    """Context manager for timing operations"""
    
    def __init__(
        self,
        monitor: PerformanceMonitor,
        metric_name: str,
        metadata: Optional[Dict] = None
    ):
        self.monitor = monitor
        self.metric_name = metric_name
        self.metadata = metadata or {}
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        self.monitor.record_metric(self.metric_name, duration, self.metadata)
    
    async def __aenter__(self):
        self.start_time = time.time()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        self.monitor.record_metric(self.metric_name, duration, self.metadata)


# Decorators for automatic performance tracking
def track_performance(monitor: PerformanceMonitor, metric_name: str):
    """Decorator to automatically track function performance"""
    def decorator(func):
        if asyncio.iscoroutinefunction(func):
            async def async_wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = await func(*args, **kwargs)
                    return result
                finally:
                    duration = time.time() - start_time
                    monitor.record_metric(metric_name, duration)
            return async_wrapper
        else:
            def sync_wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    duration = time.time() - start_time
                    monitor.record_metric(metric_name, duration)
            return sync_wrapper
    return decorator


if __name__ == '__main__':
    async def test():
        """Test performance monitor"""
        monitor = PerformanceMonitor()
        await monitor.start_monitoring()
        
        # Simulate some operations
        for i in range(50):
            # API requests
            monitor.record_metric('api_response', 0.1 + i * 0.01)
            
            # Database queries
            monitor.record_metric('database_query', 0.05 + i * 0.005)
            
            # Some slow operations
            if i % 10 == 0:
                monitor.record_metric('api_response', 2.0)  # Slow request
        
        # Get statistics
        stats = monitor.get_statistics()
        print("\n[+] Performance Statistics:")
        for metric, data in stats.items():
            print(f"\n  {metric}:")
            print(f"    Count: {data['count']}")
            print(f"    Mean: {data['mean']:.3f}s")
            print(f"    Median: {data['median']:.3f}s")
            print(f"    P95: {data['p95']:.3f}s")
            print(f"    P99: {data['p99']:.3f}s")
        
        # Get bottlenecks
        bottlenecks = monitor.get_bottlenecks()
        print(f"\n[!] Bottlenecks detected: {len(bottlenecks)}")
        for b in bottlenecks[:5]:
            print(f"  - {b['metric']}: {b['value']:.3f}s (threshold: {b['threshold']:.3f}s, severity: {b['severity']})")
        
        # Get report
        report = monitor.get_report()
        print(f"\n[+] Report:")
        print(f"  Uptime: {report['uptime_seconds']:.1f}s")
        print(f"  Total measurements: {report['total_measurements']}")
        print(f"  Bottlenecks: {report['bottlenecks']}")
        
        await monitor.stop_monitoring()
    
    asyncio.run(test())

