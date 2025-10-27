"""Obfuscation Agent"""
import asyncio, base64
from typing import Dict, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData

class ObfuscationAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="ObfuscationAgent", description="Obfuscate code/payloads", version="1.0.0")
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            code = strategy.get('code', '')
            method = strategy.get('method', 'base64')
            
            if method == 'base64':
                obfuscated = base64.b64encode(code.encode()).decode()
            else:
                obfuscated = code
            
            return AgentData(success=True, data={'obfuscated': obfuscated, 'method': method})
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])
