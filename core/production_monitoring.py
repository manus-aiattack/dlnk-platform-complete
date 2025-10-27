"""
Production Monitoring System
ระบบ monitoring สำหรับ production พร้อม Prometheus metrics
"""

import psutil
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from prometheus_client import Counter, Gauge, Histogram, Summary, generate_latest, REGISTRY
from core.logger import log


# Prometheus Metrics
# Counters
attack_requests_total = Counter(
    'manus_attack_requests_total',
    'Total number of attack requests',
    ['attack_type', 'status']
)

vulnerabilities_found_total = Counter(
    'manus_vulnerabilities_found_total',
    'Total number of vulnerabilities found',
    ['severity', 'type']
)

api_requests_total = Counter(
    'manus_api_requests_total',
    'Total number of API requests',
    ['method', 'endpoint', 'status']
)

errors_total = Counter(
    'manus_errors_total',
    'Total number of errors',
    ['error_type', 'component']
)

# Gauges
active_attacks = Gauge(
    'manus_active_attacks',
    'Number of currently active attacks'
)

active_agents = Gauge(
    'manus_active_agents',
    'Number of currently active agents'
)

c2_agents_connected = Gauge(
    'manus_c2_agents_connected',
    'Number of C2 agents connected'
)

fuzzing_nodes_online = Gauge(
    'manus_fuzzing_nodes_online',
    'Number of online fuzzing nodes'
)

# System metrics
cpu_usage_percent = Gauge(
    'manus_cpu_usage_percent',
    'CPU usage percentage'
)

memory_usage_percent = Gauge(
    'manus_memory_usage_percent',
    'Memory usage percentage'
)

disk_usage_percent = Gauge(
    'manus_disk_usage_percent',
    'Disk usage percentage'
)

# Histograms
attack_duration_seconds = Histogram(
    'manus_attack_duration_seconds',
    'Attack duration in seconds',
    ['attack_type'],
    buckets=[1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600]
)

api_request_duration_seconds = Histogram(
    'manus_api_request_duration_seconds',
    'API request duration in seconds',
    ['method', 'endpoint'],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5]
)

# Summaries
vulnerability_cvss_score = Summary(
    'manus_vulnerability_cvss_score',
    'CVSS scores of found vulnerabilities'
)


class ProductionMonitoring:
    """
    Production Monitoring System
    
    Features:
    - System metrics collection
    - Prometheus metrics
    - Health checks
    - Performance monitoring
    - Alert generation
    """
    
    def __init__(self):
        """Initialize production monitoring"""
        self.is_running = False
        self.monitoring_tasks = []
        self.health_status = {}
        self.alerts = []
    
    async def start(self):
        """เริ่มต้น monitoring"""
        try:
            self.is_running = True
            
            # เริ่ม monitoring tasks
            self.monitoring_tasks = [
                asyncio.create_task(self._collect_system_metrics()),
                asyncio.create_task(self._monitor_health()),
                asyncio.create_task(self._check_alerts())
            ]
            
            log.info("[ProductionMonitoring] Monitoring started")
            return True
        
        except Exception as e:
            log.error(f"[ProductionMonitoring] Failed to start: {e}")
            return False
    
    async def stop(self):
        """หยุด monitoring"""
        try:
            self.is_running = False
            
            for task in self.monitoring_tasks:
                task.cancel()
            
            self.monitoring_tasks = []
            
            log.info("[ProductionMonitoring] Monitoring stopped")
            return True
        
        except Exception as e:
            log.error(f"[ProductionMonitoring] Failed to stop: {e}")
            return False
    
    async def _collect_system_metrics(self):
        """รวบรวม system metrics"""
        while self.is_running:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                cpu_usage_percent.set(cpu_percent)
                
                # Memory usage
                memory = psutil.virtual_memory()
                memory_usage_percent.set(memory.percent)
                
                # Disk usage
                disk = psutil.disk_usage('/')
                disk_usage_percent.set(disk.percent)
                
                # Log if high usage
                if cpu_percent > 80:
                    log.warning(f"[ProductionMonitoring] High CPU usage: {cpu_percent}%")
                
                if memory.percent > 80:
                    log.warning(f"[ProductionMonitoring] High memory usage: {memory.percent}%")
                
                if disk.percent > 80:
                    log.warning(f"[ProductionMonitoring] High disk usage: {disk.percent}%")
                
                await asyncio.sleep(15)  # Collect every 15 seconds
            
            except Exception as e:
                log.error(f"[ProductionMonitoring] Error collecting system metrics: {e}")
                await asyncio.sleep(15)
    
    async def _monitor_health(self):
        """ตรวจสอบ health ของ components"""
        while self.is_running:
            try:
                # Check database
                db_healthy = await self._check_database_health()
                self.health_status['database'] = db_healthy
                
                # Check Redis
                redis_healthy = await self._check_redis_health()
                self.health_status['redis'] = redis_healthy
                
                # Check LLM
                llm_healthy = await self._check_llm_health()
                self.health_status['llm'] = llm_healthy
                
                # Overall health
                all_healthy = all(self.health_status.values())
                self.health_status['overall'] = all_healthy
                
                if not all_healthy:
                    unhealthy = [k for k, v in self.health_status.items() if not v]
                    log.warning(f"[ProductionMonitoring] Unhealthy components: {unhealthy}")
                
                await asyncio.sleep(30)  # Check every 30 seconds
            
            except Exception as e:
                log.error(f"[ProductionMonitoring] Error monitoring health: {e}")
                await asyncio.sleep(30)
    
    async def _check_database_health(self) -> bool:
        """ตรวจสอบ database health"""
        # ในระบบจริงจะเชื่อมต่อ database จริง
        return True
    
    async def _check_redis_health(self) -> bool:
        """ตรวจสอบ Redis health"""
        # ในระบบจริงจะเชื่อมต่อ Redis จริง
        return True
    
    async def _check_llm_health(self) -> bool:
        """ตรวจสอบ LLM health"""
        # ในระบบจริงจะเชื่อมต่อ LLM จริง
        return True
    
    async def _check_alerts(self):
        """ตรวจสอบและสร้าง alerts"""
        while self.is_running:
            try:
                # Check system metrics
                cpu_percent = psutil.cpu_percent()
                memory_percent = psutil.virtual_memory().percent
                disk_percent = psutil.disk_usage('/').percent
                
                # Generate alerts
                if cpu_percent > 90:
                    await self._create_alert(
                        "high_cpu_usage",
                        f"CPU usage is critically high: {cpu_percent}%",
                        "critical"
                    )
                
                if memory_percent > 90:
                    await self._create_alert(
                        "high_memory_usage",
                        f"Memory usage is critically high: {memory_percent}%",
                        "critical"
                    )
                
                if disk_percent > 90:
                    await self._create_alert(
                        "high_disk_usage",
                        f"Disk usage is critically high: {disk_percent}%",
                        "critical"
                    )
                
                # Check health status
                if not self.health_status.get('overall', True):
                    await self._create_alert(
                        "system_unhealthy",
                        "System health check failed",
                        "high"
                    )
                
                await asyncio.sleep(60)  # Check every minute
            
            except Exception as e:
                log.error(f"[ProductionMonitoring] Error checking alerts: {e}")
                await asyncio.sleep(60)
    
    async def _create_alert(self, alert_type: str, message: str, severity: str):
        """สร้าง alert"""
        alert = {
            "type": alert_type,
            "message": message,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        }
        
        self.alerts.append(alert)
        
        # Increment error counter
        errors_total.labels(error_type=alert_type, component="system").inc()
        
        log.warning(f"[ProductionMonitoring] Alert: {message}")
    
    def record_attack_request(self, attack_type: str, status: str):
        """บันทึก attack request"""
        attack_requests_total.labels(attack_type=attack_type, status=status).inc()
    
    def record_vulnerability_found(self, severity: str, vuln_type: str, cvss_score: float):
        """บันทึก vulnerability ที่พบ"""
        vulnerabilities_found_total.labels(severity=severity, type=vuln_type).inc()
        vulnerability_cvss_score.observe(cvss_score)
    
    def record_api_request(self, method: str, endpoint: str, status: int, duration: float):
        """บันทึก API request"""
        api_requests_total.labels(method=method, endpoint=endpoint, status=str(status)).inc()
        api_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)
    
    def record_attack_duration(self, attack_type: str, duration: float):
        """บันทึก attack duration"""
        attack_duration_seconds.labels(attack_type=attack_type).observe(duration)
    
    def set_active_attacks(self, count: int):
        """ตั้งค่าจำนวน active attacks"""
        active_attacks.set(count)
    
    def set_active_agents(self, count: int):
        """ตั้งค่าจำนวน active agents"""
        active_agents.set(count)
    
    def set_c2_agents_connected(self, count: int):
        """ตั้งค่าจำนวน C2 agents connected"""
        c2_agents_connected.set(count)
    
    def set_fuzzing_nodes_online(self, count: int):
        """ตั้งค่าจำนวน fuzzing nodes online"""
        fuzzing_nodes_online.set(count)
    
    def get_metrics(self) -> bytes:
        """
        รับ Prometheus metrics
        
        Returns:
            Metrics in Prometheus format
        """
        return generate_latest(REGISTRY)
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        รับ health status
        
        Returns:
            Health status dictionary
        """
        return {
            "status": "healthy" if self.health_status.get('overall', True) else "unhealthy",
            "components": self.health_status,
            "timestamp": datetime.now().isoformat()
        }
    
    def get_alerts(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        รับรายการ alerts
        
        Args:
            severity: Filter by severity (optional)
        
        Returns:
            List of alerts
        """
        if severity:
            return [a for a in self.alerts if a['severity'] == severity]
        return self.alerts


# Global instance
monitoring = ProductionMonitoring()


# Example usage
if __name__ == "__main__":
    async def main():
        # Start monitoring
        await monitoring.start()
        
        # Simulate some metrics
        monitoring.record_attack_request("web_application", "success")
        monitoring.record_vulnerability_found("critical", "SQL Injection", 9.8)
        monitoring.record_api_request("POST", "/api/attack", 200, 0.5)
        monitoring.set_active_attacks(5)
        monitoring.set_active_agents(10)
        
        # Wait a bit
        await asyncio.sleep(5)
        
        # Get metrics
        metrics = monitoring.get_metrics()
        print(metrics.decode())
        
        # Get health
        health = monitoring.get_health_status()
        print(f"\nHealth: {health}")
        
        # Stop monitoring
        await monitoring.stop()
    
    asyncio.run(main())

