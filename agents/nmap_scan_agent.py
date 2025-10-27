
import os
from core.data_models import AgentData, Strategy
from core.logger import log


from core.base_agent import BaseAgent

class NmapScanAgent(BaseAgent):
    def __init__(self, context_manager, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)

    async def run(self, strategy):
        log.info("Running Nmap Scan Agent...")
        target = self.context_manager.target_host
        shell_id = strategy.context.get("pivot_shell_id")

        # Define the output file path
        # Use /tmp for remote execution
        output_file = f"/tmp/nmap_scan_{target}.xml"

        # Construct the nmap command
        nmap_command = f"nmap -sV -T4 -oX {output_file} --top-ports 1000 {target}"

        if shell_id:
            log.info(
                f"Executing nmap command on remote shell {shell_id}: {nmap_command}")
            result = await self.context_manager.orchestrator.shell_manager.send_command(shell_id, nmap_command)
            # Note: We don't get a structured result dict from send_command, so we assume success if there is output.
            if not result:
                log.error(f"Nmap scan failed on remote shell {shell_id}.")
                return
        else:
            log.info(f"Executing nmap command locally: {nmap_command}")
            result_dict = await self.context_manager.orchestrator.run_shell_command(nmap_command, "Run Nmap scan.")
            if result_dict.get("exit_code") != 0:
                log.error(f"Nmap scan failed: {result_dict.get('stderr')}")
                return

        log.success(f"Nmap scan completed. Output saved to {output_file}")

        # The NmapParserAgent will be responsible for parsing this file
        # and putting the findings into Redis.

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute nmap scan agent"""
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
