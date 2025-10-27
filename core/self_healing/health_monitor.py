"""
Health Monitor for dLNk Attack Platform
Monitors system health and triggers recovery when needed
"""

import asyncio
import time
import psutil
from typing import Dict, List, Optional, Callable
from datetime import datetime, timedelta
from collections import defaultdict
import logging

log = logging.getLogger(__name__)


class HealthMonitor:
    """
    System Health Monitor
    
    Features:
    - Monitor all system components
    - Heartbeat checks
    - Automatic restart on failure
    - Circuit breaker pattern
    - Health status reporting
    - Dependency tracking
    """
    
    def __init__(self):
        self.components = {}
        self.health_status = {}
        self.last_check = {}
        self.failure_counts = defaultdict(int)
        self.circuit_breakers = {}
        self.recovery_callbacks = {}
        self.monitoring = False
        self.check_interval = 30  # seconds
        
        # Circuit breaker thresholds
        self.failure_threshold = 5
        self.recovery_timeout = 300  # 5 minutes
        
        # Component dependencies
        self.dependencies = {}
    
    async def start_monitoring(self):
        """Start health monitoring loop"""
        if self.monitoring:
            log.warning("[HealthMonitor] Already monitoring")
            return
        
        self.monitoring = True
        log.info("[HealthMonitor] Starting health monitoring")
        
        asyncio.create_task(self._monitoring_loop())
    
    async def stop_monitoring(self):
        """Stop health monitoring"""
        self.monitoring = False
        log.info("[HealthMonitor] Stopped health monitoring")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                await self._check_all_components()
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                log.error(f"[HealthMonitor] Monitoring loop error: {e}")
                await asyncio.sleep(self.check_interval)
    
    async def register_component(
        self,
        component_name: str,
        health_check: Callable,
        recovery_callback: Optional[Callable] = None,
        dependencies: Optional[List[str]] = None
    ):
        """
        Register a component for health monitoring
        
        Args:
            component_name: Name of the component
            health_check: Async function that returns health status
            recovery_callback: Async function to call for recovery
            dependencies: List of component names this depends on
        """
        self.components[component_name] = health_check
        
        if recovery_callback:
            self.recovery_callbacks[component_name] = recovery_callback
        
        if dependencies:
            self.dependencies[component_name] = dependencies
        
        self.health_status[component_name] = {
            'status': 'unknown',
            'last_check': None,
            'last_healthy': None,
            'consecutive_failures': 0
        }
        
        self.circuit_breakers[component_name] = {
            'state': 'closed',  # closed, open, half_open
            'opened_at': None,
            'failure_count': 0
        }
        
        log.info(f"[HealthMonitor] Registered component: {component_name}")
    
    async def _check_all_components(self):
        """Check health of all registered components"""
        log.debug("[HealthMonitor] Checking all components...")
        
        for component_name in self.components:
            await self._check_component(component_name)
    
    async def _check_component(self, component_name: str) -> bool:
        """
        Check health of a specific component
        
        Args:
            component_name: Name of the component
        
        Returns:
            True if healthy, False otherwise
        """
        if component_name not in self.components:
            log.error(f"[HealthMonitor] Unknown component: {component_name}")
            return False
        
        # Check circuit breaker
        breaker = self.circuit_breakers[component_name]
        if breaker['state'] == 'open':
            # Check if recovery timeout has passed
            if breaker['opened_at']:
                time_since_open = time.time() - breaker['opened_at']
                if time_since_open >= self.recovery_timeout:
                    log.info(f"[HealthMonitor] Circuit breaker half-open for {component_name}")
                    breaker['state'] = 'half_open'
                else:
                    log.debug(f"[HealthMonitor] Circuit breaker open for {component_name}")
                    return False
        
        # Check dependencies first
        if component_name in self.dependencies:
            for dep in self.dependencies[component_name]:
                if not await self._is_component_healthy(dep):
                    log.warning(f"[HealthMonitor] {component_name} dependency {dep} is unhealthy")
                    self._record_failure(component_name, reason=f"dependency {dep} failed")
                    return False
        
        # Perform health check
        try:
            health_check = self.components[component_name]
            is_healthy = await health_check()
            
            current_time = time.time()
            self.last_check[component_name] = current_time
            
            if is_healthy:
                self._record_success(component_name)
                return True
            else:
                self._record_failure(component_name)
                return False
                
        except Exception as e:
            log.error(f"[HealthMonitor] Health check failed for {component_name}: {e}")
            self._record_failure(component_name, reason=str(e))
            return False
    
    def _record_success(self, component_name: str):
        """Record successful health check"""
        status = self.health_status[component_name]
        status['status'] = 'healthy'
        status['last_check'] = datetime.now()
        status['last_healthy'] = datetime.now()
        status['consecutive_failures'] = 0
        
        # Reset circuit breaker
        breaker = self.circuit_breakers[component_name]
        if breaker['state'] == 'half_open':
            log.info(f"[HealthMonitor] Circuit breaker closed for {component_name}")
            breaker['state'] = 'closed'
            breaker['failure_count'] = 0
        
        self.failure_counts[component_name] = 0
    
    def _record_failure(self, component_name: str, reason: str = 'unknown'):
        """Record failed health check and trigger recovery if needed"""
        status = self.health_status[component_name]
        status['status'] = 'unhealthy'
        status['last_check'] = datetime.now()
        status['consecutive_failures'] += 1
        
        self.failure_counts[component_name] += 1
        
        log.warning(
            f"[HealthMonitor] {component_name} unhealthy "
            f"(failures: {status['consecutive_failures']}, reason: {reason})"
        )
        
        # Update circuit breaker
        breaker = self.circuit_breakers[component_name]
        breaker['failure_count'] += 1
        
        # Open circuit breaker if threshold reached
        if breaker['failure_count'] >= self.failure_threshold and breaker['state'] == 'closed':
            log.error(f"[HealthMonitor] Opening circuit breaker for {component_name}")
            breaker['state'] = 'open'
            breaker['opened_at'] = time.time()
        
        # Trigger recovery
        if status['consecutive_failures'] >= 3:
            asyncio.create_task(self._trigger_recovery(component_name))
    
    async def _trigger_recovery(self, component_name: str):
        """Trigger recovery for failed component"""
        log.info(f"[HealthMonitor] Triggering recovery for {component_name}")
        
        if component_name in self.recovery_callbacks:
            try:
                recovery_callback = self.recovery_callbacks[component_name]
                success = await recovery_callback()
                
                if success:
                    log.info(f"[HealthMonitor] Recovery successful for {component_name}")
                    self._record_success(component_name)
                else:
                    log.error(f"[HealthMonitor] Recovery failed for {component_name}")
            except Exception as e:
                log.error(f"[HealthMonitor] Recovery error for {component_name}: {e}")
        else:
            log.warning(f"[HealthMonitor] No recovery callback for {component_name}")
    
    async def _is_component_healthy(self, component_name: str) -> bool:
        """Check if component is currently healthy"""
        if component_name not in self.health_status:
            return False
        
        status = self.health_status[component_name]
        return status['status'] == 'healthy'
    
    async def get_health_status(self, component_name: Optional[str] = None) -> Dict:
        """
        Get health status of component(s)
        
        Args:
            component_name: Specific component, or None for all
        
        Returns:
            Health status information
        """
        if component_name:
            if component_name not in self.health_status:
                return {'error': f'Unknown component: {component_name}'}
            
            return {
                'component': component_name,
                **self.health_status[component_name],
                'circuit_breaker': self.circuit_breakers[component_name]['state']
            }
        else:
            # Return all components
            return {
                'components': {
                    name: {
                        **status,
                        'circuit_breaker': self.circuit_breakers[name]['state']
                    }
                    for name, status in self.health_status.items()
                },
                'overall_status': self._calculate_overall_status()
            }
    
    def _calculate_overall_status(self) -> str:
        """Calculate overall system health status"""
        if not self.health_status:
            return 'unknown'
        
        healthy_count = sum(
            1 for status in self.health_status.values()
            if status['status'] == 'healthy'
        )
        total_count = len(self.health_status)
        
        if healthy_count == total_count:
            return 'healthy'
        elif healthy_count >= total_count * 0.7:
            return 'degraded'
        else:
            return 'critical'
    
    async def force_check(self, component_name: str) -> bool:
        """Force immediate health check of component"""
        log.info(f"[HealthMonitor] Force checking {component_name}")
        return await self._check_component(component_name)
    
    async def reset_circuit_breaker(self, component_name: str):
        """Manually reset circuit breaker for component"""
        if component_name in self.circuit_breakers:
            self.circuit_breakers[component_name] = {
                'state': 'closed',
                'opened_at': None,
                'failure_count': 0
            }
            log.info(f"[HealthMonitor] Reset circuit breaker for {component_name}")
    
    def get_statistics(self) -> Dict:
        """Get monitoring statistics"""
        return {
            'total_components': len(self.components),
            'healthy_components': sum(
                1 for s in self.health_status.values()
                if s['status'] == 'healthy'
            ),
            'unhealthy_components': sum(
                1 for s in self.health_status.values()
                if s['status'] == 'unhealthy'
            ),
            'open_circuit_breakers': sum(
                1 for cb in self.circuit_breakers.values()
                if cb['state'] == 'open'
            ),
            'failure_counts': dict(self.failure_counts),
            'monitoring_active': self.monitoring
        }


# Pre-defined health check functions
class HealthChecks:
    """Collection of common health check functions"""
    
    @staticmethod
    async def check_api_server(host: str = 'localhost', port: int = 8000) -> bool:
        """Check if API server is responding"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'http://{host}:{port}/health',
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    return response.status == 200
        except:
            return False
    
    @staticmethod
    async def check_database(connection_string: str) -> bool:
        """Check if database is accessible"""
        try:
            import asyncpg
            conn = await asyncpg.connect(connection_string, timeout=5)
            await conn.execute('SELECT 1')
            await conn.close()
            return True
        except:
            return False
    
    @staticmethod
    async def check_redis(host: str = 'localhost', port: int = 6379) -> bool:
        """Check if Redis is accessible"""
        try:
            import aioredis
            redis = await aioredis.create_redis_pool(f'redis://{host}:{port}', timeout=5)
            await redis.ping()
            redis.close()
            await redis.wait_closed()
            return True
        except:
            return False
    
    @staticmethod
    async def check_disk_space(threshold_percent: float = 90.0) -> bool:
        """Check if disk space is below threshold"""
        try:
            disk = psutil.disk_usage('/')
            return disk.percent < threshold_percent
        except:
            return False
    
    @staticmethod
    async def check_memory(threshold_percent: float = 90.0) -> bool:
        """Check if memory usage is below threshold"""
        try:
            memory = psutil.virtual_memory()
            return memory.percent < threshold_percent
        except:
            return False
    
    @staticmethod
    async def check_cpu(threshold_percent: float = 95.0) -> bool:
        """Check if CPU usage is below threshold"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            return cpu_percent < threshold_percent
        except:
            return False


if __name__ == '__main__':
    async def test():
        """Test health monitor"""
        monitor = HealthMonitor()
        
        # Register components
        await monitor.register_component(
            'api_server',
            lambda: HealthChecks.check_api_server(),
            recovery_callback=lambda: asyncio.sleep(1)  # Mock recovery
        )
        
        await monitor.register_component(
            'disk_space',
            lambda: HealthChecks.check_disk_space()
        )
        
        await monitor.register_component(
            'memory',
            lambda: HealthChecks.check_memory()
        )
        
        # Start monitoring
        await monitor.start_monitoring()
        
        # Wait and check status
        await asyncio.sleep(5)
        
        status = await monitor.get_health_status()
        print(f"\n[+] Health Status:")
        print(f"  Overall: {status['overall_status']}")
        for name, comp_status in status['components'].items():
            print(f"  {name}: {comp_status['status']} (CB: {comp_status['circuit_breaker']})")
        
        stats = monitor.get_statistics()
        print(f"\n[+] Statistics: {stats}")
        
        await monitor.stop_monitoring()
    
    asyncio.run(test())

