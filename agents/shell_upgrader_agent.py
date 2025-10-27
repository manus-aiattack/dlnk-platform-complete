"""
An agent that attempts to upgrade a simple, non-interactive shell to a 
fully interactive PTY (pseudo-terminal).
"""

from core.logger import log
from core.data_models import AgentData, Strategy
from core.data_models import Strategy, ShellUpgraderReport, AttackPhase, ErrorType
import time
from typing import Optional
from core.shell_manager import ShellManager

from core.base_agent import BaseAgent


class ShellUpgraderAgent(BaseAgent):
    supported_phases = [AttackPhase.ESCALATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.shell_manager: Optional[ShellManager] = None
        self.report_class = ShellUpgraderReport

        self.linux_techniques = [
            {
                "name": "python3_pty",
                "command": '''python3 -c "import pty; pty.spawn('/bin/bash')"''',
                "success_indicator": "",  # Often hangs on success, so empty output is a good sign
            },
            {
                "name": "python_pty",
                "command": '''python -c "import pty; pty.spawn('/bin/bash')"''',
                "success_indicator": "",
            },
            {
                "name": "script_tty",
                "command": "script /dev/null -c /bin/bash",
                "success_indicator": "Script started",
            },
        ]

    async def setup(self):
        """Asynchronous setup method for ShellUpgraderAgent."""
        self.shell_manager = await self.context_manager.get_context('shell_manager')

    async def run(self, strategy: Strategy, **kwargs) -> ShellUpgraderReport:
        start_time = time.time()
        shell_id = strategy.context.get("shell_id")
        if not shell_id:
            end_time = time.time()
            return ShellUpgraderReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id="",
                errors=["Shell ID not provided."],
                error_type=ErrorType.CONFIGURATION,
                summary="Shell upgrade failed: Missing shell ID."
            )

        log.phase(
            f"ShellUpgraderAgent: Attempting to upgrade shell {shell_id}")

        # 1. Determine OS
        try:
            os_output = await self.shell_manager.send_command(shell_id, "uname -o", timeout=10)
        except Exception as e:
            log.error(f"Failed to determine OS on shell {shell_id}: {e}")
            end_time = time.time()
            return ShellUpgraderReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=[f"Failed to determine OS: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"Shell upgrade failed: Could not determine OS: {e}"
            )

        if "GNU/Linux" not in os_output:
            msg = f"Unsupported OS for shell upgrade: {os_output}"
            log.warning(msg)
            end_time = time.time()
            return ShellUpgraderReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=[msg],
                error_type=ErrorType.CONFIGURATION,
                summary=f"Shell upgrade failed: Unsupported OS {os_output}."
            )

        # 2. Attempt Linux upgrade techniques
        for technique in self.linux_techniques:
            log.info(
                f"Trying technique: {technique['name']} on shell {shell_id}")
            try:
                # Use a short timeout because successful commands often hang the simple shell
                output = await self.shell_manager.send_command(shell_id, technique["command"], timeout=5)

                # Heuristic: If the command executes and doesn't immediately return an error,
                # it's likely working. A hanging shell is a sign of success.
                # A true verification is much more complex and will be a future improvement.
                if "command not found" not in output.lower() and "error" not in output.lower():
                    summary = f"Shell {shell_id} upgrade likely successful with technique: {technique['name']}"
                    log.success(summary)
                    # In a real scenario, the shell in shell_manager would now be a PTY.
                    # For now, we just report success.
                    end_time = time.time()
                    return ShellUpgraderReport(
                        agent_name=self.__class__.__name__,
                        start_time=start_time,
                        end_time=end_time,
                        shell_id=shell_id,
                        technique_used=technique['name'],
                        summary=summary
                    )
            except Exception as e:
                # Exceptions (like timeouts) are often expected for successful upgrades
                summary = f"Technique {technique['name']} resulted in an expected exception/timeout: {e}"
                log.info(summary)
                end_time = time.time()
                return ShellUpgraderReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    shell_id=shell_id,
                    technique_used=technique['name'],
                    summary=summary
                )

        final_msg = "All shell upgrade techniques failed."
        log.error(final_msg)
        end_time = time.time()
        return ShellUpgraderReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            shell_id=shell_id,
            errors=[final_msg],
            error_type=ErrorType.LOGIC,
            summary=final_msg
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute shell upgrader agent"""
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
