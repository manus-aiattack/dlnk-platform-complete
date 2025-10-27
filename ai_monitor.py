#!/usr/bin/env python3
"""
dLNk AI Monitoring Agent
Autonomous system monitoring and self-healing
"""

import asyncio
import sys
import subprocess
import psutil
from pathlib import Path
from datetime import datetime
from loguru import logger

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

class AIMonitor:
    """AI-powered system monitoring and self-healing"""
    
    def __init__(self):
        self.services = [
            'dlnk-platform',
            'dlnk-terminal',
            'dlnk-c2',
            'postgresql',
            'redis-server',
            'ttyd'
        ]
        self.check_interval = 30  # seconds
        self.restart_threshold = 3  # restart after 3 failures
        self.failure_counts = {service: 0 for service in self.services}
        
    async def check_service(self, service_name):
        """Check if a service is running"""
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', service_name],
                capture_output=True,
                text=True
            )
            return result.stdout.strip() == 'active'
        except Exception as e:
            logger.error(f"[AI Monitor] Error checking {service_name}: {e}")
            return False
    
    async def restart_service(self, service_name):
        """Restart a failed service"""
        try:
            logger.warning(f"[AI Monitor] Restarting {service_name}...")
            subprocess.run(['sudo', 'systemctl', 'restart', service_name])
            await asyncio.sleep(5)
            
            if await self.check_service(service_name):
                logger.success(f"[AI Monitor] ✅ {service_name} restarted successfully")
                self.failure_counts[service_name] = 0
                return True
            else:
                logger.error(f"[AI Monitor] ❌ {service_name} failed to restart")
                return False
        except Exception as e:
            logger.error(f"[AI Monitor] Error restarting {service_name}: {e}")
            return False
    
    async def check_system_resources(self):
        """Check system resources"""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Alert if resources are high
        if cpu_percent > 90:
            logger.warning(f"[AI Monitor] ⚠️ High CPU usage: {cpu_percent}%")
        
        if memory.percent > 90:
            logger.warning(f"[AI Monitor] ⚠️ High memory usage: {memory.percent}%")
        
        if disk.percent > 90:
            logger.warning(f"[AI Monitor] ⚠️ High disk usage: {disk.percent}%")
        
        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'disk_percent': disk.percent
        }
    
    async def monitor_loop(self):
        """Main monitoring loop"""
        logger.info("[AI Monitor] 🤖 AI Monitoring Agent started")
        logger.info(f"[AI Monitor] Monitoring {len(self.services)} services")
        logger.info(f"[AI Monitor] Check interval: {self.check_interval}s")
        
        while True:
            try:
                # Check all services
                for service in self.services:
                    is_running = await self.check_service(service)
                    
                    if not is_running:
                        self.failure_counts[service] += 1
                        logger.error(
                            f"[AI Monitor] ❌ {service} is down "
                            f"(failures: {self.failure_counts[service]})"
                        )
                        
                        # Auto-restart if threshold reached
                        if self.failure_counts[service] >= self.restart_threshold:
                            await self.restart_service(service)
                    else:
                        # Reset failure count if service is running
                        if self.failure_counts[service] > 0:
                            logger.info(f"[AI Monitor] ✅ {service} recovered")
                            self.failure_counts[service] = 0
                
                # Check system resources
                resources = await self.check_system_resources()
                
                # Log status every 10 minutes
                if datetime.now().minute % 10 == 0 and datetime.now().second < self.check_interval:
                    logger.info(
                        f"[AI Monitor] 📊 System Status - "
                        f"CPU: {resources['cpu_percent']:.1f}% | "
                        f"Memory: {resources['memory_percent']:.1f}% | "
                        f"Disk: {resources['disk_percent']:.1f}%"
                    )
                
                # Wait before next check
                await asyncio.sleep(self.check_interval)
                
            except KeyboardInterrupt:
                logger.info("[AI Monitor] Shutting down...")
                break
            except Exception as e:
                logger.error(f"[AI Monitor] Error in monitoring loop: {e}")
                await asyncio.sleep(self.check_interval)
    
    async def run(self):
        """Run the AI monitor"""
        try:
            await self.monitor_loop()
        except Exception as e:
            logger.error(f"[AI Monitor] Fatal error: {e}")
            return 1
        return 0

async def main():
    """Main entry point"""
    monitor = AIMonitor()
    return await monitor.run()

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except Exception as e:
        logger.error(f"[AI Monitor] Fatal error: {e}")
        sys.exit(1)

