import asyncio
from core.data_models import AgentData, Strategy
import psutil # For system monitoring
from core.base_agent import BaseAgent
from core.data_models import Strategy, ResourceManagerReport, ErrorType
from core.logger import log
import time
from typing import List

class ResourceManagerAgent(BaseAgent):
    """
    Monitors system resources and provides recommendations for adaptive resource allocation.
    """
    required_tools = [] # Uses psutil, which is a Python library

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pubsub_manager = self.orchestrator.pubsub_manager
        self.cpu_threshold = 80 # %
        self.memory_threshold = 80 # %
        self.network_threshold = 100 * 1024 * 1024 # 100 MB/s
        self.last_net_io = psutil.net_io_counters()
        self.last_check_time = time.time()
        self.report_class = ResourceManagerReport

    async def run(self, strategy: Strategy) -> ResourceManagerReport:
        start_time = time.time()
        log.info("ResourceManagerAgent: Monitoring system resources...")
        
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        net_io = psutil.net_io_counters()

        current_time = time.time()
        time_diff = current_time - self.last_check_time
        
        bytes_sent_diff = net_io.bytes_sent - self.last_net_io.bytes_sent
        bytes_recv_diff = net_io.bytes_recv - self.last_net_io.bytes_recv
        
        send_speed = (bytes_sent_diff / time_diff) if time_diff > 0 else 0
        recv_speed = (bytes_recv_diff / time_diff) if time_diff > 0 else 0

        self.last_net_io = net_io
        self.last_check_time = current_time

        recommendations: List[str] = []
        if cpu_percent > self.cpu_threshold:
            recommendations.append("Reduce CPU-intensive tasks (e.g., fuzzing, heavy scanning).")
        if memory_percent > self.memory_threshold:
            recommendations.append("Reduce memory-intensive tasks.")
        if send_speed > self.network_threshold or recv_speed > self.network_threshold:
            recommendations.append("Reduce network-intensive tasks (e.g., large file transfers, aggressive scanning).")

        summary: str
        if recommendations:
            summary = "System resources are under strain. Recommendations: " + " ".join(recommendations)
            log.warning(f"ResourceManagerAgent: {summary}")
            await self.pubsub_manager.publish(
                "resource_events",
                {
                    "event_type": "RESOURCE_STRAIN",
                    "resource_status": {
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory_percent,
                        "network_send_speed_mbps": send_speed / (1024 * 1024),
                        "network_recv_speed_mbps": recv_speed / (1024 * 1024)
                    },
                    "recommendations": recommendations,
                    "timestamp": time.time()
                }
            )
        else:
            summary = "System resources are operating within normal limits."
            log.info(f"ResourceManagerAgent: {summary}")
        
        end_time = time.time()
        return self.create_report(
            summary=summary,
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            network_send_speed_mbps=send_speed / (1024 * 1024),
            network_recv_speed_mbps=recv_speed / (1024 * 1024),
            recommendations=recommendations
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute resource manager agent"""
        try:
            target = strategy.context.get('target_url', '')
            
            # Call existing method
            if asyncio.iscoroutinefunction(self.run):
                results = await self.run(target)
            else:
                results = self.run(target)
            
            return AgentData(
                agent_name=self.__class__.__name__,
                success=True,
                summary=f"{self.__class__.__name__} completed successfully",
                errors=[],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={'results': results}
            )
        except Exception as e:
            return AgentData(
                agent_name=self.__class__.__name__,
                success=False,
                summary=f"{self.__class__.__name__} failed",
                errors=[str(e)],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={}
            )
