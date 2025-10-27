from core.logger import log
from core.data_models import AgentData, Strategy
from core.data_models import Strategy, ShellReport, ErrorType, AttackPhase
from typing import Optional, Dict, Any

from core.base_agent import BaseAgent
import time
import time
import time
import time


class ShellAgent(BaseAgent):
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD, AttackPhase.LATERAL_MOVEMENT, AttackPhase.PERSISTENCE, AttackPhase.ESCALATION]
    required_tools = [] # This agent interacts with ShellManager, not external tools directly

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = ShellReport

    async def _run_command(self, shell_id: str, command: str) -> Dict[str, Any]:
        """
        Sends a command to a specific shell.
        """
        log.info(f"Shell Agent: Sending command to shell {shell_id}: {command}")
        try:
            output = await self.orchestrator.shell_manager.send_command(shell_id, command)
            summary = f"Command executed on shell {shell_id}."
            return {"summary": summary, "output": output, "shell_id": shell_id, "command": command}
        except Exception as e:
            error_msg = f"Failed to execute command on shell {shell_id}: {e}"
            log.error(error_msg, exc_info=True)
            return {"summary": error_msg, "errors": [error_msg], "shell_id": shell_id, "command": command}

    async def _list_shells(self) -> Dict[str, Any]:
        """
        Gets a dictionary of active shells.
        """
        log.info("Shell Agent: Requesting list of active shells.")
        try:
            shells = self.orchestrator.shell_manager.list_shells()
            summary = f"Found {len(shells)} active shells."
            return {"summary": summary, "shells": shells}
        except Exception as e:
            error_msg = f"Failed to list shells: {e}"
            log.error(error_msg, exc_info=True)
            return {"summary": error_msg, "errors": [error_msg]}

    async def _get_shell_info(self, shell_id: str) -> Dict[str, Any]:
        """
        Gets information about a specific shell.
        """
        log.info(f"Shell Agent: Requesting information about shell {shell_id}.")
        try:
            info = self.orchestrator.shell_manager.get_shell_info(shell_id)
            if info:
                summary = f"Information for shell {shell_id} retrieved."
                return {"summary": summary, "shell_id": shell_id, "info": info}
            else:
                error_msg = f"Shell {shell_id} not found."
                return {"summary": error_msg, "errors": [error_msg], "shell_id": shell_id}
        except Exception as e:
            error_msg = f"Failed to get info for shell {shell_id}: {e}"
            log.error(error_msg, exc_info=True)
            return {"summary": error_msg, "errors": [error_msg], "shell_id": shell_id}

    async def _close_shell(self, shell_id: str) -> Dict[str, Any]:
        """
        Closes a specific shell.
        """
        log.info(f"Shell Agent: Closing shell {shell_id}.")
        try:
            success = self.orchestrator.shell_manager.close_shell(shell_id)
            if success:
                summary = f"Shell {shell_id} closed successfully."
                return {"summary": summary, "shell_id": shell_id}
            else:
                error_msg = f"Failed to close shell {shell_id}."
                return {"summary": error_msg, "errors": [error_msg], "shell_id": shell_id}
        except Exception as e:
            error_msg = f"Failed to close shell {shell_id}: {e}"
            log.error(error_msg, exc_info=True)
            return {"summary": error_msg, "errors": [error_msg], "shell_id": shell_id}

    async def run(self, strategy: Strategy, **kwargs) -> ShellReport:
        start_time = time.time()
        action = strategy.context.get("action")
        shell_id = strategy.context.get("shell_id")
        command = strategy.context.get("command")

        result: Dict[str, Any] = {"summary": "Unknown shell action.", "errors": ["Unknown action."]}
        error_type = ErrorType.LOGIC

        if action == "run_command":
            if shell_id and command:
                result = await self._run_command(shell_id, command)
            else:
                result = {"summary": "Missing shell_id or command for run_command action.", "errors": ["Missing parameters."]}
                error_type = ErrorType.CONFIGURATION
        elif action == "list_shells":
            result = await self._list_shells()
        elif action == "get_shell_info":
            if shell_id:
                result = await self._get_shell_info(shell_id)
            else:
                result = {"summary": "Missing shell_id for get_shell_info action.", "errors": ["Missing parameters."]}
                error_type = ErrorType.CONFIGURATION
        elif action == "close_shell":
            if shell_id:
                result = await self._close_shell(shell_id)
            else:
                result = {"summary": "Missing shell_id for close_shell action.", "errors": ["Missing parameters."]}
                error_type = ErrorType.CONFIGURATION
        else:
            log.error(f"ShellAgent: Unknown action received: {action}")

        end_time = time.time()
        return self.create_report(
            summary=result.get("summary", ""),
            errors=result.get("errors"),
            error_type=error_type if result.get("errors") else None,
            action=action,
            shell_id=result.get("shell_id"),
            command=result.get("command"),
            output=result.get("output"),
            shells=result.get("shells")
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute shell agent"""
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
