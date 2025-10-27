import asyncio
import time
from typing import Dict, List, Any, Optional
from core.logger import log
from datetime import datetime


class MonitoringSystem:
    """ระบบ monitoring สำหรับติดตามการทำงานของระบบ"""

    def __init__(self):
        self.metrics = {}
        self.alerts = []
        self.is_monitoring = False
        self.monitoring_tasks = []

    async def start(self):
        """เริ่มต้น monitoring"""
        try:
            self.is_monitoring = True

            # เริ่มต้น monitoring tasks
            self.monitoring_tasks = [
                asyncio.create_task(self._monitor_system_health()),
                asyncio.create_task(self._monitor_performance()),
                asyncio.create_task(self._monitor_errors())
            ]

            log.info("✅ เริ่มต้น monitoring system")
            return True

        except Exception as e:
            log.error(f"❌ เริ่มต้น monitoring system ล้มเหลว: {e}")
            return False

    async def stop(self):
        """หยุด monitoring"""
        try:
            self.is_monitoring = False

            # หยุด monitoring tasks
            for task in self.monitoring_tasks:
                task.cancel()

            self.monitoring_tasks = []

            log.info("✅ หยุด monitoring system")
            return True

        except Exception as e:
            log.error(f"❌ หยุด monitoring system ล้มเหลว: {e}")
            return False

    async def _monitor_system_health(self):
        """ติดตามสุขภาพของระบบ"""
        while self.is_monitoring:
            try:
                # ตรวจสอบสุขภาพของระบบ
                health_status = await self._check_system_health()

                # บันทึก metrics
                self.metrics["system_health"] = health_status

                # ตรวจสอบ alerts
                if health_status.get("status") == "unhealthy":
                    await self._create_alert("system_health", "System health is unhealthy", "high")

                await asyncio.sleep(10)  # ตรวจสอบทุก 10 วินาที

            except Exception as e:
                log.error(f"❌ ตรวจสอบ system health ล้มเหลว: {e}")
                await asyncio.sleep(10)

    async def _monitor_performance(self):
        """ติดตามประสิทธิภาพของระบบ"""
        while self.is_monitoring:
            try:
                # ตรวจสอบประสิทธิภาพ
                performance_metrics = await self._check_performance()

                # บันทึก metrics
                self.metrics["performance"] = performance_metrics

                # ตรวจสอบ alerts
                if performance_metrics.get("cpu_usage", 0) > 80:
                    await self._create_alert("performance", "High CPU usage detected", "medium")

                if performance_metrics.get("memory_usage", 0) > 80:
                    await self._create_alert("performance", "High memory usage detected", "medium")

                await asyncio.sleep(30)  # ตรวจสอบทุก 30 วินาที

            except Exception as e:
                log.error(f"❌ ตรวจสอบ performance ล้มเหลว: {e}")
                await asyncio.sleep(30)

    async def _monitor_errors(self):
        """ติดตาม errors"""
        while self.is_monitoring:
            try:
                # ตรวจสอบ errors
                error_count = await self._check_error_count()

                # บันทึก metrics
                self.metrics["errors"] = error_count

                # ตรวจสอบ alerts
                if error_count > 10:
                    await self._create_alert("errors", "High error count detected", "high")

                await asyncio.sleep(60)  # ตรวจสอบทุก 60 วินาที

            except Exception as e:
                log.error(f"❌ ตรวจสอบ errors ล้มเหลว: {e}")
                await asyncio.sleep(60)

    async def _check_system_health(self) -> Dict[str, Any]:
        """ตรวจสอบสุขภาพของระบบ"""
        try:
            # ตรวจสอบการทำงานของระบบ
            health_status = {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "components": {
                    "database": "healthy",
                    "llm": "healthy",
                    "agents": "healthy",
                    "monitoring": "healthy"
                }
            }

            # ตรวจสอบ components
            # (ในระบบจริงจะตรวจสอบการทำงานของ components จริง)

            return health_status

        except Exception as e:
            log.error(f"❌ ตรวจสอบ system health ล้มเหลว: {e}")
            return {"status": "unhealthy", "error": str(e)}

    async def _check_performance(self) -> Dict[str, Any]:
        """ตรวจสอบประสิทธิภาพของระบบ"""
        try:
            # ตรวจสอบประสิทธิภาพ
            performance_metrics = {
                "timestamp": datetime.now().isoformat(),
                "cpu_usage": 0,  # ใช้ psutil ในระบบจริง
                "memory_usage": 0,  # ใช้ psutil ในระบบจริง
                "disk_usage": 0,  # ใช้ psutil ในระบบจริง
                "network_usage": 0,  # ใช้ psutil ในระบบจริง
                "active_connections": 0,
                "active_processes": 0
            }

            return performance_metrics

        except Exception as e:
            log.error(f"❌ ตรวจสอบ performance ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _check_error_count(self) -> int:
        """ตรวจสอบจำนวน errors"""
        try:
            # ตรวจสอบจำนวน errors
            # (ในระบบจริงจะตรวจสอบจาก log files หรือ error tracking)
            return 0

        except Exception as e:
            log.error(f"❌ ตรวจสอบ error count ล้มเหลว: {e}")
            return 0

    async def _create_alert(self, alert_type: str, message: str, severity: str):
        """สร้าง alert"""
        try:
            alert = {
                "id": f"{alert_type}_{int(time.time())}",
                "type": alert_type,
                "message": message,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
                "status": "active"
            }

            self.alerts.append(alert)

            # แสดง alert
            log.warning(f"🚨 ALERT [{severity.upper()}]: {message}")

        except Exception as e:
            log.error(f"❌ สร้าง alert ล้มเหลว: {e}")

    async def get_metrics(self) -> Dict[str, Any]:
        """รับ metrics"""
        return self.metrics

    async def get_alerts(self, status: str = None) -> List[Dict[str, Any]]:
        """รับ alerts"""
        if status:
            return [alert for alert in self.alerts if alert.get("status") == status]
        return self.alerts

    async def acknowledge_alert(self, alert_id: str) -> bool:
        """ยืนยัน alert"""
        try:
            for alert in self.alerts:
                if alert.get("id") == alert_id:
                    alert["status"] = "acknowledged"
                    alert["acknowledged_at"] = datetime.now().isoformat()
                    return True

            return False

        except Exception as e:
            log.error(f"❌ ยืนยัน alert ล้มเหลว: {e}")
            return False

    async def resolve_alert(self, alert_id: str) -> bool:
        """แก้ไข alert"""
        try:
            for alert in self.alerts:
                if alert.get("id") == alert_id:
                    alert["status"] = "resolved"
                    alert["resolved_at"] = datetime.now().isoformat()
                    return True

            return False

        except Exception as e:
            log.error(f"❌ แก้ไข alert ล้มเหลว: {e}")
            return False

    async def get_system_status(self) -> Dict[str, Any]:
        """รับสถานะของระบบ"""
        try:
            status = {
                "monitoring_active": self.is_monitoring,
                "metrics_count": len(self.metrics),
                "alerts_count": len(self.alerts),
                "active_alerts": len([a for a in self.alerts if a.get("status") == "active"]),
                "acknowledged_alerts": len([a for a in self.alerts if a.get("status") == "acknowledged"]),
                "resolved_alerts": len([a for a in self.alerts if a.get("status") == "resolved"]),
                "timestamp": datetime.now().isoformat()
            }

            return status

        except Exception as e:
            log.error(f"❌ รับ system status ล้มเหลว: {e}")
            return {"error": str(e)}
