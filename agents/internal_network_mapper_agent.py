import asyncio
from core.data_models import AgentData, Strategy
from core.data_models import InternalScanReport, Strategy, LiveHost, ErrorType
from core.logger import log
from core.shell_manager import ShellManager
from core.target_model_manager import TargetModelManager
from typing import Optional
from core.base_agent import BaseAgent
import time


class InternalNetworkMapperAgent(BaseAgent):
    """An agent to scan the internal network from a compromised host."""

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.shell_manager: Optional[ShellManager] = None
        self.target_model_manager: Optional[TargetModelManager] = None
        self.report_class = InternalScanReport # Set report class

    async def setup(self):
        """Asynchronous setup method for InternalNetworkMapperAgent."""
        self.shell_manager = await self.context_manager.get_context('shell_manager')
        self.target_model_manager = await self.context_manager.get_context('target_model_manager')

    async def run(self, strategy: Strategy) -> InternalScanReport:
        start_time = time.time()
        shell_id = strategy.context.get("shell_id")
        target_subnet = strategy.context.get(
            "target_subnet")  # e.g., "10.1.1.0/24"
        # The host from which we are pivoting
        origin_host = strategy.context.get("origin_host")

        if not all([shell_id, target_subnet, origin_host]):
            end_time = time.time()
            return InternalScanReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary="Missing shell_id, target_subnet, or origin_host in context.",
                errors=["Missing shell_id, target_subnet, or origin_host in context."],
                error_type=ErrorType.CONFIGURATION
            )

        if not await self.shell_manager.is_shell_active(shell_id):
            end_time = time.time()
            return InternalScanReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=f"Shell {shell_id} is not active.",
                errors=[f"Shell {shell_id} is not active."],
                error_type=ErrorType.NETWORK
            )

        log.info(
            f"[InternalNetworkMapperAgent] Starting internal scan on {target_subnet} via shell {shell_id}")

        command = f"nmap -T4 -F --open {target_subnet}"

        try:
            nmap_output = await self.shell_manager.send_command(shell_id, command, timeout=300)

            if "Nmap done" not in nmap_output:
                error_msg = f"Nmap scan may have failed. Output: {nmap_output}"
                log.error(f"[InternalNetworkMapperAgent] {error_msg}")
                end_time = time.time()
                return InternalScanReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    summary=error_msg,
                    errors=[error_msg],
                    error_type=ErrorType.LOGIC,
                    raw_output=nmap_output
                )

            log.success(
                f"[InternalNetworkMapperAgent] Internal scan of {target_subnet} completed.")

            live_hosts = self._parse_nmap_output(nmap_output)
            end_time = time.time()
            report = InternalScanReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=f"Found {len(live_hosts)} live hosts in {target_subnet}.",
                raw_output=nmap_output,
                live_hosts=live_hosts
            )

            # Save the report to the origin host's target model
            target_model = self.target_model_manager.get_or_create_target(
                origin_host)
            target_model.update_from_internal_scan_report(report)
            self.target_model_manager.save_model(target_model)

            return report

        except Exception as e:
            log.critical(
                f"[InternalNetworkMapperAgent] An unexpected error occurred: {e}")
            end_time = time.time()
            return InternalScanReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=f"An error occurred: {e}",
                errors=[str(e)],
                error_type=ErrorType.LOGIC
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute internal network mapper agent"""
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

    def _parse_nmap_output(self, nmap_output: str) -> list[LiveHost]:
        """Parses the nmap output to extract live hosts and their open ports."""
        hosts = []
        current_host_ip = None
        current_ports = []

        for line in nmap_output.splitlines():
            if line.startswith("Nmap scan report for"):
                if current_host_ip:
                    hosts.append(
                        LiveHost(ip=current_host_ip, ports=current_ports))

                current_host_ip = line.split("for ")[-1].strip()
                current_ports = []

            elif "/tcp" in line and "open" in line:
                parts = line.split()
                port = parts[0].split('/')[0]
                service = parts[2]
                current_ports.append({"port": int(port), "service": service})

        if current_host_ip:
            hosts.append(LiveHost(ip=current_host_ip, ports=current_ports))

        return hosts
