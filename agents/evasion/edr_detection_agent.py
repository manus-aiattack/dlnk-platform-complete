"""EDR Detection Agent - Detect presence of EDR/XDR/AV"""
import asyncio, os, psutil
from typing import Dict, Any, List
from core.base_agent import BaseAgent
from core.agent_data import AgentData

class EDRDetectionAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="EDRDetectionAgent", description="Detect EDR/XDR/AV presence", version="1.0.0")
        self.edr_processes = ['cylance', 'cb.exe', 'tanium', 'crowdstrike', 'sentinelone', 'defender', 'sophos', 'kaspersky', 'mcafee', 'symantec', 'trendmicro']
        self.edr_drivers = ['cylancedrvx64', 'cbk7', 'parity.sys', 'csagent.sys', 'sentinelmonitor.sys']
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            detected_processes = []
            for proc in psutil.process_iter(['name']):
                proc_name = proc.info['name'].lower()
                if any(edr in proc_name for edr in self.edr_processes):
                    detected_processes.append(proc.info['name'])
            
            detected_drivers = []
            if os.name == 'nt':
                import winreg
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services')
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        subkey_name = winreg.EnumKey(key, i)
                        if any(drv in subkey_name.lower() for drv in self.edr_drivers):
                            detected_drivers.append(subkey_name)
                except Exception as e:
                    print("Error occurred")
            
            edr_detected = len(detected_processes) > 0 or len(detected_drivers) > 0
            
            return AgentData(success=True, data={'edr_detected': edr_detected, 'processes': detected_processes, 'drivers': detected_drivers})
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])
