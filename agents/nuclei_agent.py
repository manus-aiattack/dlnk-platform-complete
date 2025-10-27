import os
from core.data_models import AgentData, Strategy
import json
from core.data_models import ScannerReport, Strategy, ScanIntensity, AttackPhase, ErrorType
from core.logger import log
from config import settings
import time

from core.base_agent import BaseAgent


class NucleiAgent(BaseAgent):
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD]
    required_tools = ["nuclei"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = ScannerReport # Set report class

    async def run(self, strategy: Strategy, **kwargs) -> ScannerReport:
        start_time = time.time()
        target_url = await self.context_manager.get_context('target_url')
        target_host = await self.context_manager.get_context('target_host')
        log.info(
            f"[NucleiAgent] Running Nuclei against {target_url} with intensity {strategy.scan_intensity.name}...")

        # Define the output path for the JSON report
        output_dir = os.path.join(settings.WORKSPACE_DIR, "nuclei_reports")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(
            output_dir, f"{target_host}.json")

        # Construct the Nuclei command
        command = [
            settings.NUCLEI_PATH,
            "-u", target_url,
        ]

        # Add scan intensity flags
        if strategy.scan_intensity == ScanIntensity.STEALTH:
            command.extend(["-rate-limit", "5", "-bulk-size", "5"])
        elif strategy.scan_intensity == ScanIntensity.NORMAL:
            command.extend(["-rate-limit", "50", "-bulk-size", "25"])
        elif strategy.scan_intensity == ScanIntensity.AGGRESSIVE:
            command.extend(["-rate-limit", "150", "-bulk-size", "100"])

        # Add remaining flags
        command.extend([
            "-s", "high,critical",
            "-jsonl",
            "-o", output_path,
            "-silent"
        ])

        try:
            result = await self.orchestrator.run_shell_command(" ".join(command), f"Run Nuclei scan with {strategy.scan_intensity.name} intensity.")

            if not result:
                log.error(
                    "[NucleiAgent] Scan failed because the command returned no result.")
                end_time = time.time()
                return ScannerReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    errors=["Nuclei command returned no result."],
                    error_type=ErrorType.LOGIC,
                    summary="Nuclei scan failed: Command returned no result."
                )

            if result.get('exit_code') == 0:
                # Check if the report file was actually created and has content
                if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                    log.success(
                        f"[NucleiAgent] Scan completed. Report saved to {output_path}")
                    # The analyzer agent will be responsible for parsing this.
                    end_time = time.time()
                    return ScannerReport(
                        agent_name=self.__class__.__name__,
                        start_time=start_time,
                        end_time=end_time,
                        findings=[],  # To be populated by the analyzer
                        summary=f"Nuclei scan completed. Report at {output_path}",
                        raw_report_path=output_path
                    )
                else:
                    # Scan was successful but found no vulnerabilities, so no report was generated.
                    log.info(
                        "[NucleiAgent] Scan completed successfully, but no vulnerabilities were found.")
                    end_time = time.time()
                    return ScannerReport(
                        agent_name=self.__class__.__name__,
                        start_time=start_time,
                        end_time=end_time,
                        findings=[],
                        summary="Scan completed. No vulnerabilities found.",
                        raw_report_path=None
                    )
            else:
                error_message = result.get('stderr') or result.get(
                    'error') or "Unknown Nuclei error"
                log.error(f"[NucleiAgent] Scan failed: {error_message}")
                end_time = time.time()
                return ScannerReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    errors=[error_message],
                    error_type=ErrorType.LOGIC,
                    summary=f"Nuclei scan failed: {error_message}"
                )

        except Exception as e:
            log.error(
                f"[NucleiAgent] An unexpected error occurred: {e}", exc_info=True)
            end_time = time.time()
            return ScannerReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=[str(e)],
                error_type=ErrorType.LOGIC,
                summary=f"Nuclei scan failed due to an unexpected error: {e}"
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute nuclei agent"""
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
