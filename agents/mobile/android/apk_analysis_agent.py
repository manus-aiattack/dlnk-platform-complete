"""APK Analysis Agent"""
import asyncio, os, zipfile, xml.etree.ElementTree as ET
from typing import Dict, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData

class APKAnalysisAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="APKAnalysisAgent", description="Analyze Android APK files", version="1.0.0")
        self.output_dir = "workspace/apk_analysis"
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        try:
            apk_path = strategy.get('apk_path')
            if not apk_path or not os.path.exists(apk_path):
                return AgentData(success=False, errors=["APK file not found"])
            
            analysis = await self._analyze_apk(apk_path)
            return AgentData(success=True, data=analysis)
        except Exception as e:
            return AgentData(success=False, errors=[str(e)])
    
    async def _analyze_apk(self, apk_path):
        analysis = {'file': apk_path, 'permissions': [], 'activities': [], 'services': []}
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                if 'AndroidManifest.xml' in apk.namelist():
                    manifest = apk.read('AndroidManifest.xml')
                    analysis['has_manifest'] = True
        except Exception as e:
            print("Error occurred")
        
        return analysis
