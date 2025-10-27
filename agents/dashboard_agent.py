import asyncio
from core.data_models import AgentData, Strategy
import time
import httpx
from core.data_models import MonitorReport, Finding, Strategy, DashboardReport, ErrorType # Added DashboardReport, ErrorType
from core.logger import log

from core.base_agent import BaseAgent


class DashboardAgent(BaseAgent):
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.pubsub_manager = orchestrator.pubsub_manager
        self.is_running = False
        self.report_class = DashboardReport # Set report class

    async def run(self, strategy: Strategy = None, **kwargs) -> DashboardReport:
        start_time = time.time()
        log.info("DashboardAgent: Starting to listen for agent events...")
        self.is_running = True
        
        try:
            await self.pubsub_manager.subscribe("agent_events", self._process_agent_event)
            
            # Return a success report immediately, then continue listening in the background
            end_time = time.time()
            report = DashboardReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary="DashboardAgent started successfully and is listening for events.",
                status_message="Listening for events"
            )
            asyncio.create_task(self._listen_indefinitely()) # Start background listening
            return report
        except Exception as e:
            end_time = time.time()
            return DashboardReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=[f"Failed to start DashboardAgent: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"DashboardAgent failed to start: {e}"
            )

    async def _listen_indefinitely(self):
        """Keeps the agent running indefinitely to listen for events."""
        while self.is_running:
            await asyncio.sleep(1) # Sleep to prevent busy-waiting

    async def _process_agent_event(self, event_data: dict):
        log.debug(f"DashboardAgent: Received agent event: {event_data}")
        # Forward the event data to the dashboard
        await self.orchestrator.send_dashboard_update(event_data)

    async def stop(self):
        log.info("DashboardAgent: Stopping event listener.")
        self.is_running = False
        # Unsubscribe from channels if necessary, though the pubsub_manager will close on orchestrator shutdown

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute dashboard agent"""
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
