
import asyncio
from core.data_models import AgentData, Strategy
from core.logger import log
from core.data_models import Strategy, DefensiveCountermeasuresReport, AttackPhase, ErrorType
from core.target_model_manager import TargetModel
from typing import Optional
from core.shell_manager import ShellManager
from core.target_model_manager import TargetModelManager
import time

from core.base_agent import BaseAgent


class DefensiveCountermeasuresAgent(BaseAgent):
    supported_phases = [AttackPhase.DEFENSE_EVASION]
    required_tools = []
    """An agent to detect defensive tools like AV and EDR on a target system."""

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.shell_manager: Optional[ShellManager] = None
        self.target_model_manager: Optional[TargetModelManager] = None
        self.report_class = DefensiveCountermeasuresReport # Set report class

        self.defense_keywords = {
            # EDR
            "crowdstrike": ["falcon", "cs.falcon"],
            "sentinelone": ["sentinel", "sentinelone"],
            "carbonblack": ["cb.exe", "carbonblack"],
            "cybereason": ["cybereason"],
            # AV
            "mcafee": ["mcafee", "masvc"],
            "symantec": ["symantec", "sep"],
            "kaspersky": ["kaspersky", "kav"],
            "bitdefender": ["bitdefender", "bdagent"],
            "eset": ["eset", "ekrn"],
            "avast": ["avast"],
            "avg": ["avg"],
            "clamav": ["clamd", "clamav"],
            "sophos": ["sophos"],
            # Windows Defender
            "microsoft": ["msmpeng", "nissrv", "windefend"]}

    async def setup(self):
        """Asynchronous setup method for DefensiveCountermeasuresAgent."""
        self.shell_manager = await self.context_manager.get_context('shell_manager')
        self.target_model_manager = await self.context_manager.get_context('target_model_manager')

    async def run(self, strategy: Strategy, **kwargs) -> DefensiveCountermeasuresReport:
        start_time = time.time()
        shell_id = strategy.context.get("shell_id")
        if not shell_id:
            end_time = time.time()
            return DefensiveCountermeasuresReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id="",
                errors=["Shell ID not provided."],
                error_type=ErrorType.CONFIGURATION,
                summary="Defensive countermeasures scan failed: Missing shell ID."
            )

        log.phase(
            f"DefensiveCountermeasuresAgent: Checking for defensive tools on shell {shell_id}")

        # Determine OS to run the correct command
        os_check_output = await self.shell_manager.send_command(shell_id, "uname -a")
        is_linux = "linux" in os_check_output.lower()

        if is_linux:
            process_list_output = await self.shell_manager.send_command(shell_id, "ps aux")
        else:
            process_list_output = await self.shell_manager.send_command(shell_id, "tasklist")

        if not process_list_output:
            end_time = time.time()
            return DefensiveCountermeasuresReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=["Failed to get process list."],
                error_type=ErrorType.NETWORK,
                summary="Defensive countermeasures scan failed: Could not retrieve process list."
            )

        detected_tools = set()
        process_list_lower = process_list_output.lower()

        for tool, keywords in self.defense_keywords.items():
            for keyword in keywords:
                if keyword in process_list_lower:
                    detected_tools.add(tool)
                    log.warning(
                        f"Detected potential defensive tool: {tool} (keyword: {keyword}")
                    break  # Move to the next tool once a keyword is found

        detected_tools_list = list(detected_tools)

        # Update the target model
        target_model = self.target_model_manager.get_target(
            strategy.context.get("hostname"))
        if target_model:
            # Combine new findings with existing ones, avoiding duplicates
            existing_tools = set(target_model.defensive_tools)
            updated_tools = list(existing_tools.union(detected_tools))
            if len(updated_tools) > len(existing_tools):
                target_model.defensive_tools = updated_tools
                self.target_model_manager.save_model(target_model)
                log.info(
                    f"Updated TargetModel with detected defensive tools: {detected_tools_list}")

        summary = f"Scan complete. Found {len(detected_tools_list)} potential defensive tools: {detected_tools_list}"
        log.success(summary)
        end_time = time.time()
        return DefensiveCountermeasuresReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            shell_id=shell_id,
            detected_tools=detected_tools_list,
            summary=summary
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute defensive countermeasures agent"""
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
