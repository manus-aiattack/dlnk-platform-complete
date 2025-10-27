
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
import re
from core.logger import log
from core.data_models import Strategy, AgentData, Credential, DataDumpReport, InfiltratorReport, AttackPhase, ErrorType
from typing import Optional
from core.shell_manager import ShellManager
from core.target_model_manager import TargetModelManager
import time


class CredentialParserReport(AgentData):
    credentials_found: int = 0
    summary: str = ""


class CredentialParserAgent(BaseAgent):
    # Assuming AttackPhase enum is not available
    supported_phases = ["POST_EXPLOITATION"]
    required_tools = []
    """An agent that parses reports from other agents to find credentials."""

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.shell_manager: Optional[ShellManager] = None
        self.target_model_manager: Optional[TargetModelManager] = None
        self.report_class = CredentialParserReport # Set report class
        # Regex to find password-like strings, e.g., password = "secret123"
        self.password_regex = re.compile(
            r"(password|pass|pwd|secret|token)[\'\"\s=:]+([^\'\"\s]+)", re.IGNORECASE)

    async def setup(self):
        """Asynchronous setup method for CredentialParserAgent."""
        self.shell_manager = await self.context_manager.get_context('shell_manager')
        self.target_model_manager = await self.context_manager.get_context('target_model_manager')

    async def run(self, strategy: Strategy, **kwargs) -> CredentialParserReport:
        start_time = time.time()
        log.info("CredentialParserAgent: Parsing previous reports for credentials...")
        
        credentials_found_count = 0

        # For now, we'll look at the latest DataDumpReport and InfiltratorReport
        data_dump_report = await self.context_manager.get_context("data_dump_report")
        infiltrator_report = await self.context_manager.get_context("infiltrator_report")

        if data_dump_report:
            credentials_found_count += await self._parse_data_dump_report(data_dump_report)

        if infiltrator_report:
            credentials_found_count += await self._parse_infiltrator_report(infiltrator_report)

        end_time = time.time()
        summary = f"Found {credentials_found_count} potential credentials."
        return CredentialParserReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            credentials_found=credentials_found_count,
            summary=summary
        )

    async def _parse_data_dump_report(self, data_dump_report: DataDumpReport) -> int:
        count = 0
        if not data_dump_report.dumped_data:
            return count

        for data_type, content in data_dump_report.dumped_data.items():
            if "passwords" in data_type or "secrets" in data_type or "tokens" in data_type:
                count += await self._find_creds_in_text(
                    content, data_dump_report.shell_id, data_type)
        return count

    async def _parse_infiltrator_report(self, infiltrator_report: InfiltratorReport) -> int:
        count = 0
        if not infiltrator_report.findings:
            return count

        for finding in infiltrator_report.findings:
            count += await self._find_creds_in_text(
                finding.value, infiltrator_report.shell_id, finding.source)
        return count

    async def _find_creds_in_text(self, text: str, shell_id: str, source: str) -> int:
        count = 0
        shell_info = await self.shell_manager.get_shell_info(shell_id)
        target_host = shell_info.get("host")
        target_model = self.target_model_manager.get_or_create_target(
            target_host)

        for line in text.splitlines():
            matches = self.password_regex.finditer(line)
            for match in matches:
                password = match.group(2)
                if len(password) < 4:  # Avoid short, likely false positives
                    continue

                log.success(
                    f"Found potential password in '{source}': {password}")
                cred = Credential(
                    host=target_host,
                    password=password,
                    source_agent="CredentialParserAgent",
                    source_file=source
                )
                target_model.credentials.append(cred)
                count += 1

        self.target_model_manager.save_model(
            target_model)
        return count

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute credential parser agent"""
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
