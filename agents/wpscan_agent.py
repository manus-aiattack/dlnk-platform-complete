from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
from core.data_models import Strategy, WpscanReport, AttackPhase, ErrorType
from core.logger import log
from config import settings
import asyncio
import json
import time


class WpscanAgent(BaseAgent):
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = ["wpscan"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = WpscanReport

    async def run(self, strategy: Strategy, **kwargs) -> WpscanReport:
        start_time = time.time()
        target_url = strategy.context.get(
            "target_url")
        if not target_url:
            target_url = await self.context_manager.get_context('target_url')
        log.info(f"Running WPScan on {target_url}")
        
        try:
            command = [
                settings.WPSCAN_PATH,
                "--url",
                target_url,
                "--api-token",
                settings.WPSCAN_API_KEY,
                "-f",
                "json",
                "-e",
                "vp,vt",
            ]
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                raw_output = stdout.decode()
                findings = self.parse_findings(
                    json.loads(raw_output))
                summary = f"WPScan completed successfully for {target_url}. Found {len(findings)} findings."
                end_time = time.time()
                return WpscanReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    target_url=target_url,
                    raw_output=raw_output,
                    findings=findings,
                    summary=summary
                )
            else:
                error_message = stderr.decode()
                log.error(f"WPScan failed with error: {error_message}")
                end_time = time.time()
                return WpscanReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    target_url=target_url,
                    errors=[error_message],
                    error_type=ErrorType.LOGIC,
                    summary=f"WPScan failed for {target_url} with error: {error_message}"
                )

        except Exception as e:
            error_message = str(e)
            log.error(f"An error occurred while running WPScan: {e}")
            end_time = time.time()
            return WpscanReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                target_url=target_url,
                errors=[error_message],
                error_type=ErrorType.LOGIC,
                summary=f"An unexpected error occurred during WPScan for {target_url}: {error_message}"
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute wpscan agent"""
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

    def parse_findings(self, data: dict) -> list:
        findings = []
        if "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                findings.append(
                    {
                        "title": vuln["title"],
                        "references": vuln["references"],
                        "fixed_in": vuln.get("fixed_in", "N/A")
                    }
                )
        return findings
