"""
External Tool Integration Manager
จัดการ external security tools (Nuclei, Nikto, WPScan, Gobuster, Hydra, etc.)
"""

import os
import asyncio
import subprocess
from typing import Dict, List, Any, Optional
from loguru import logger
from core.error_handlers import handle_errors


class ToolManager:
    """
    จัดการ external security tools
    
    Supported Tools:
    - Nuclei - Vulnerability scanner
    - Nikto - Web server scanner
    - WPScan - WordPress scanner
    - Gobuster - Directory/DNS bruteforcer
    - Hydra - Login bruteforcer
    - John the Ripper - Password cracker
    - Hashcat - Advanced password cracker
    - Nmap - Network scanner (already integrated)
    - SQLMap - SQL injection (already integrated)
    - Metasploit - Exploitation framework (already integrated)
    """
    
    def __init__(self):
        self.tools = {
            "nuclei": os.getenv("NUCLEI_PATH", "nuclei"),
            "nikto": os.getenv("NIKTO_PATH", "nikto"),
            "wpscan": os.getenv("WPSCAN_PATH", "wpscan"),
            "gobuster": os.getenv("GOBUSTER_PATH", "gobuster"),
            "hydra": os.getenv("HYDRA_PATH", "hydra"),
            "john": os.getenv("JOHN_PATH", "john"),
            "hashcat": os.getenv("HASHCAT_PATH", "hashcat"),
            "nmap": os.getenv("NMAP_PATH", "nmap"),
            "sqlmap": os.getenv("SQLMAP_PATH", "sqlmap"),
            "msfconsole": os.getenv("METASPLOIT_PATH", "msfconsole")
        }
        
        self.workspace_dir = os.getenv("WORKSPACE_DIR", "workspace")
        self.results_dir = os.path.join(self.workspace_dir, "loot", "tool_results")
        os.makedirs(self.results_dir, exist_ok=True)
    
    def check_tool_installed(self, tool_name: str) -> bool:
        """ตรวจสอบว่า tool ติดตั้งแล้วหรือไม่"""
        tool_path = self.tools.get(tool_name)
        if not tool_path:
            return False
        
        try:
            result = subprocess.run(
                [tool_path, "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"Tool {tool_name} not found: {e}")
            return False
    
    @handle_errors(default_return={})
    async def run_nuclei(
        self,
        target: str,
        templates: Optional[List[str]] = None,
        severity: str = "critical,high,medium"
    ) -> Dict[str, Any]:
        """
        Run Nuclei vulnerability scanner
        
        Args:
            target: Target URL or IP
            templates: List of template paths (optional)
            severity: Severity filter (default: critical,high,medium)
        
        Returns:
            Scan results
        """
        logger.info(f"[Nuclei] Scanning {target}")
        
        output_file = os.path.join(self.results_dir, f"nuclei_{target.replace('://', '_').replace('/', '_')}.json")
        
        cmd = [
            self.tools["nuclei"],
            "-u", target,
            "-severity", severity,
            "-json",
            "-o", output_file
        ]
        
        if templates:
            for template in templates:
                cmd.extend(["-t", template])
        
        timeout = int(os.getenv("TOOL_TIMEOUT", "300"))
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            # Parse results
            import json
            results = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            results.append(json.loads(line))
                        except Exception as e:
                            print("Error occurred")
            
            logger.success(f"[Nuclei] Found {len(results)} vulnerabilities")
            
            return {
                "success": True,
                "tool": "nuclei",
                "target": target,
                "vulnerabilities": results,
                "output_file": output_file
            }
            
        except asyncio.TimeoutError:
            logger.error(f"[Nuclei] Scan timed out after {timeout}s")
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            logger.error(f"[Nuclei] Scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    @handle_errors(default_return={})
    async def run_nikto(self, target: str) -> Dict[str, Any]:
        """
        Run Nikto web server scanner
        
        Args:
            target: Target URL
        
        Returns:
            Scan results
        """
        logger.info(f"[Nikto] Scanning {target}")
        
        output_file = os.path.join(self.results_dir, f"nikto_{target.replace('://', '_').replace('/', '_')}.xml")
        
        cmd = [
            self.tools["nikto"],
            "-h", target,
            "-Format", "xml",
            "-output", output_file
        ]
        
        timeout = int(os.getenv("TOOL_TIMEOUT", "300"))
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            logger.success(f"[Nikto] Scan complete")
            
            return {
                "success": True,
                "tool": "nikto",
                "target": target,
                "output_file": output_file
            }
            
        except asyncio.TimeoutError:
            logger.error(f"[Nikto] Scan timed out after {timeout}s")
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            logger.error(f"[Nikto] Scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    @handle_errors(default_return={})
    async def run_wpscan(
        self,
        target: str,
        enumerate: str = "vp,vt,u"
    ) -> Dict[str, Any]:
        """
        Run WPScan WordPress scanner
        
        Args:
            target: WordPress site URL
            enumerate: What to enumerate (vp=vulnerable plugins, vt=vulnerable themes, u=users)
        
        Returns:
            Scan results
        """
        logger.info(f"[WPScan] Scanning {target}")
        
        output_file = os.path.join(self.results_dir, f"wpscan_{target.replace('://', '_').replace('/', '_')}.json")
        
        cmd = [
            self.tools["wpscan"],
            "--url", target,
            "--enumerate", enumerate,
            "--format", "json",
            "--output", output_file
        ]
        
        # Add API token if available
        api_token = os.getenv("WPSCAN_API_TOKEN", "")
        if api_token:
            cmd.extend(["--api-token", api_token])
        
        timeout = int(os.getenv("TOOL_TIMEOUT", "300"))
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            # Parse results
            import json
            results = {}
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    results = json.load(f)
            
            logger.success(f"[WPScan] Scan complete")
            
            return {
                "success": True,
                "tool": "wpscan",
                "target": target,
                "results": results,
                "output_file": output_file
            }
            
        except asyncio.TimeoutError:
            logger.error(f"[WPScan] Scan timed out after {timeout}s")
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            logger.error(f"[WPScan] Scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    @handle_errors(default_return={})
    async def run_gobuster(
        self,
        target: str,
        mode: str = "dir",
        wordlist: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run Gobuster directory/DNS bruteforcer
        
        Args:
            target: Target URL or domain
            mode: "dir" for directory bruteforce, "dns" for DNS bruteforce
            wordlist: Path to wordlist file
        
        Returns:
            Scan results
        """
        logger.info(f"[Gobuster] Running {mode} mode on {target}")
        
        if not wordlist:
            wordlist = os.getenv("GOBUSTER_WORDLIST", "/usr/share/wordlists/dirb/common.txt")
        
        output_file = os.path.join(self.results_dir, f"gobuster_{mode}_{target.replace('://', '_').replace('/', '_')}.txt")
        
        cmd = [
            self.tools["gobuster"],
            mode,
            "-u" if mode == "dir" else "-d", target,
            "-w", wordlist,
            "-o", output_file
        ]
        
        timeout = int(os.getenv("TOOL_TIMEOUT", "300"))
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            # Parse results
            results = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    results = f.readlines()
            
            logger.success(f"[Gobuster] Found {len(results)} results")
            
            return {
                "success": True,
                "tool": "gobuster",
                "mode": mode,
                "target": target,
                "results": results,
                "output_file": output_file
            }
            
        except asyncio.TimeoutError:
            logger.error(f"[Gobuster] Scan timed out after {timeout}s")
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            logger.error(f"[Gobuster] Scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    @handle_errors(default_return={})
    async def run_hydra(
        self,
        target: str,
        service: str,
        username: Optional[str] = None,
        username_list: Optional[str] = None,
        password_list: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run Hydra login bruteforcer
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username (optional)
            username_list: Path to username list (optional)
            password_list: Path to password list
        
        Returns:
            Cracked credentials
        """
        logger.info(f"[Hydra] Bruteforcing {service} on {target}")
        
        if not password_list:
            password_list = os.getenv("HYDRA_PASSWORD_LIST", "/usr/share/wordlists/rockyou.txt")
        
        output_file = os.path.join(self.results_dir, f"hydra_{service}_{target}.txt")
        
        cmd = [
            self.tools["hydra"],
            "-o", output_file
        ]
        
        if username:
            cmd.extend(["-l", username])
        elif username_list:
            cmd.extend(["-L", username_list])
        
        cmd.extend(["-P", password_list])
        cmd.extend([target, service])
        
        timeout = int(os.getenv("TOOL_TIMEOUT", "600"))
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            # Parse results
            credentials = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        if "login:" in line and "password:" in line:
                            credentials.append(line.strip())
            
            logger.success(f"[Hydra] Found {len(credentials)} credentials")
            
            return {
                "success": True,
                "tool": "hydra",
                "service": service,
                "target": target,
                "credentials": credentials,
                "output_file": output_file
            }
            
        except asyncio.TimeoutError:
            logger.error(f"[Hydra] Bruteforce timed out after {timeout}s")
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            logger.error(f"[Hydra] Bruteforce failed: {e}")
            return {"success": False, "error": str(e)}
    
    def get_available_tools(self) -> List[str]:
        """รายการ tools ที่ติดตั้งแล้ว"""
        available = []
        for tool_name in self.tools.keys():
            if self.check_tool_installed(tool_name):
                available.append(tool_name)
        return available
    
    def get_tool_info(self) -> Dict[str, Any]:
        """ข้อมูล tools ทั้งหมด"""
        info = {}
        for tool_name, tool_path in self.tools.items():
            info[tool_name] = {
                "path": tool_path,
                "installed": self.check_tool_installed(tool_name)
            }
        return info

