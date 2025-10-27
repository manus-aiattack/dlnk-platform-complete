"""Sandbox Detection Agent"""
import asyncio, os, time
from typing import Dict, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData

class SandboxDetectionAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="SandboxDetectionAgent", description="Detect sandbox environments", version="1.0.0")
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            checks = {
                'vm_artifacts': await self._check_vm_artifacts(),
                'timing': await self._check_timing(),
                'user_interaction': await self._check_user_interaction()
            }
            
            is_sandbox = any(checks.values())
            return AgentData(success=True, data={'is_sandbox': is_sandbox, 'checks': checks})
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])
    
    async def _check_vm_artifacts(self):
        vm_files = ['/sys/class/dmi/id/product_name', '/sys/class/dmi/id/sys_vendor']
        for f in vm_files:
            if os.path.exists(f):
                with open(f, 'r') as file:
                    content = file.read().lower()
                    if any(vm in content for vm in ['vmware', 'virtualbox', 'qemu', 'xen']):
                        return True
        return False
    
    async def _check_timing(self):
        start = time.time()
        await asyncio.sleep(1)
        elapsed = time.time() - start
        return elapsed < 0.9 or elapsed > 1.1
    
    async def _check_user_interaction(self):
        return False
