
from core.data_models import InterestingFinding, AgentData, AttackPhase, Strategy, DirsearchParserReport, ErrorType
from core.data_models import AgentData, Strategy
from core.logger import log
import json
from typing import Optional
from core.database_manager import DatabaseManager
import time

from core.base_agent import BaseAgent


class DirsearchParserAgent(BaseAgent):
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.database_manager: Optional[DatabaseManager] = None
        self.report_class = DirsearchParserReport

    async def setup(self):
        """Asynchronous setup method for DirsearchParserAgent."""
        self.database_manager = await self.context_manager.get_context('database_manager')

    async def run(self, strategy: Strategy, **kwargs) -> AgentData:
        start_time = time.time()
        report_path = strategy.context.get("report_path")
        if not report_path:
            end_time = time.time()
            return DirsearchParserReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=["Missing report_path in strategy context."],
                error_type=ErrorType.CONFIGURATION,
                summary="Dirsearch parsing failed: Report path not provided."
            )

        log.info(f"[DirsearchParser] Parsing report: {report_path}")
        findings = []
        try:
            with open(report_path, 'r') as f:
                report_data = json.load(f)
                results = report_data.get('results', [])
                for result in results:
                    url = result.get('url')
                    status = result.get('status')
                    if url and 200 <= status < 400:
                        finding = self._analyze_url(url, result)
                        if finding:
                            findings.append(finding)
                            # Write to Redis
                            await self.database_manager.add_finding(
                                await self.context_manager.get_context('target_host'),
                                'dirsearch',
                                finding.finding,
                                finding.context
                            )

        except FileNotFoundError:
            log.error(
                f"[DirsearchParser] Report file not found: {report_path}")
            end_time = time.time()
            return DirsearchParserReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=[f"Report file not found: {report_path}"],
                error_type=ErrorType.CONFIGURATION,
                summary=f"Dirsearch parsing failed: Report file not found at {report_path}."
            )
        except json.JSONDecodeError as e:
            log.error(
                f"[DirsearchParser] Invalid JSON in report {report_path}: {e}")
            end_time = time.time()
            return DirsearchParserReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=[f"Invalid JSON in report {report_path}: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"Dirsearch parsing failed: Invalid JSON in report {report_path}."
            )
        except Exception as e:
            log.error(
                f"[DirsearchParser] Error parsing report {report_path}: {e}", exc_info=True)
            end_time = time.time()
            return DirsearchParserReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=[f"Error parsing report {report_path}: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"Dirsearch parsing failed due to an unexpected error: {e}"
            )

        summary = f"Found {len(findings)} interesting findings."
        log.success(f"[DirsearchParser] {summary}")
        end_time = time.time()
        return DirsearchParserReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            findings=findings,
            summary=summary
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute parser dirsearch agent"""
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

    def _analyze_url(self, url: str, data: dict) -> InterestingFinding | None:
        """Analyzes a single URL to determine if it's a high-value target."""
        high_value_keywords = ['login', 'admin', 'dashboard', 'api', 'auth',
                               'user', 'pass', 'key', 'token', 'jwt', 'secret', 'backup', '.git', '.env']

        for keyword in high_value_keywords:
            if keyword in url.lower():
                return InterestingFinding(
                    finding=f"High-value keyword '{keyword}' found in URL: {url}",
                    reasoning=f"The URL contains the keyword '{keyword}', which often indicates a sensitive area.",
                    next_steps=f"Further investigate {url} for vulnerabilities. Check for default credentials, API key exposure, or information disclosure.",
                    context=data
                )
        return None
