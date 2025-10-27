"""
Agent Executor Service
รัน Attack Agents และจัดการผลลัพธ์
"""

import asyncio
import traceback
from typing import Dict, Any, List, Optional
from datetime import datetime
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from api.services.agent_registry import get_agent_registry


class AgentExecutor:
    """Service สำหรับรัน Attack Agents"""
    
    def __init__(self):
        self.registry = get_agent_registry()
        self.running_agents: Dict[str, Any] = {}
    
    async def execute_agent(
        self,
        agent_name: str,
        target_url: str,
        options: Dict[str, Any] = None,
        attack_id: str = None
    ) -> Dict[str, Any]:
        """รัน Agent และส่งคืนผลลัพธ์"""
        
        if options is None:
            options = {}
        
        # Get agent class
        agent_class = self.registry.get_agent(agent_name)
        if agent_class is None:
            return {
                "success": False,
                "error": f"Agent '{agent_name}' not found",
                "agent": agent_name,
                "target": target_url
            }
        
        # Prepare result
        result = {
            "agent": agent_name,
            "target": target_url,
            "started_at": datetime.now().isoformat(),
            "success": False,
            "vulnerabilities": [],
            "output": "",
            "error": None
        }
        
        try:
            # Instantiate agent
            agent = agent_class(target_url=target_url, **options)
            
            # Store running agent
            if attack_id:
                self.running_agents[f"{attack_id}_{agent_name}"] = agent
            
            # Execute agent
            # Try different execution methods based on agent type
            if hasattr(agent, 'run'):
                agent_result = await self._run_async(agent.run)
            elif hasattr(agent, 'execute'):
                agent_result = await self._run_async(agent.execute)
            elif hasattr(agent, 'scan'):
                agent_result = await self._run_async(agent.scan)
            elif hasattr(agent, 'attack'):
                agent_result = await self._run_async(agent.attack)
            else:
                raise AttributeError(f"Agent '{agent_name}' has no executable method")
            
            # Process result
            result["success"] = True
            result["completed_at"] = datetime.now().isoformat()
            
            # Extract vulnerabilities
            if isinstance(agent_result, dict):
                result["output"] = str(agent_result)
                
                # Check for vulnerabilities
                if "vulnerabilities" in agent_result:
                    result["vulnerabilities"] = agent_result["vulnerabilities"]
                elif "findings" in agent_result:
                    result["vulnerabilities"] = agent_result["findings"]
                elif "results" in agent_result:
                    result["vulnerabilities"] = agent_result["results"]
                
                # Check for success flag
                if "success" in agent_result:
                    result["success"] = agent_result["success"]
                
            elif isinstance(agent_result, list):
                result["vulnerabilities"] = agent_result
                result["output"] = f"Found {len(agent_result)} vulnerabilities"
            
            else:
                result["output"] = str(agent_result)
            
        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
            result["traceback"] = traceback.format_exc()
            result["completed_at"] = datetime.now().isoformat()
        
        finally:
            # Remove from running agents
            if attack_id:
                key = f"{attack_id}_{agent_name}"
                if key in self.running_agents:
                    del self.running_agents[key]
        
        return result
    
    async def _run_async(self, func, *args, **kwargs):
        """รัน function แบบ async (รองรับทั้ง sync และ async functions)"""
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            # Run sync function in executor
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, func, *args, **kwargs)
    
    async def execute_multiple_agents(
        self,
        agent_names: List[str],
        target_url: str,
        options: Dict[str, Any] = None,
        attack_id: str = None,
        parallel: bool = True
    ) -> List[Dict[str, Any]]:
        """รันหลาย Agents พร้อมกัน"""
        
        if parallel:
            # Run agents in parallel
            tasks = [
                self.execute_agent(agent_name, target_url, options, attack_id)
                for agent_name in agent_names
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Convert exceptions to error results
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed_results.append({
                        "agent": agent_names[i],
                        "target": target_url,
                        "success": False,
                        "error": str(result),
                        "traceback": traceback.format_exception(type(result), result, result.__traceback__)
                    })
                else:
                    processed_results.append(result)
            
            return processed_results
        
        else:
            # Run agents sequentially
            results = []
            for agent_name in agent_names:
                result = await self.execute_agent(agent_name, target_url, options, attack_id)
                results.append(result)
            
            return results
    
    async def execute_workflow(
        self,
        workflow_config: Dict[str, Any],
        target_url: str,
        attack_id: str = None
    ) -> Dict[str, Any]:
        """รัน Workflow ตาม configuration"""
        
        workflow_result = {
            "workflow": workflow_config.get("name", "unknown"),
            "target": target_url,
            "started_at": datetime.now().isoformat(),
            "phases": [],
            "total_vulnerabilities": 0,
            "success": True
        }
        
        try:
            # Execute each phase
            phases = workflow_config.get("phases", [])
            
            for phase in phases:
                phase_name = phase.get("name", "unknown")
                agents = phase.get("agents", [])
                parallel = phase.get("parallel", True)
                
                print(f"Executing phase: {phase_name} with {len(agents)} agents")
                
                # Execute agents in this phase
                phase_results = await self.execute_multiple_agents(
                    agents,
                    target_url,
                    options=phase.get("options", {}),
                    attack_id=attack_id,
                    parallel=parallel
                )
                
                # Count vulnerabilities
                phase_vulns = sum(len(r.get("vulnerabilities", [])) for r in phase_results)
                
                workflow_result["phases"].append({
                    "name": phase_name,
                    "agents": agents,
                    "results": phase_results,
                    "vulnerabilities_found": phase_vulns,
                    "completed_at": datetime.now().isoformat()
                })
                
                workflow_result["total_vulnerabilities"] += phase_vulns
            
            workflow_result["completed_at"] = datetime.now().isoformat()
            
        except Exception as e:
            workflow_result["success"] = False
            workflow_result["error"] = str(e)
            workflow_result["traceback"] = traceback.format_exc()
            workflow_result["completed_at"] = datetime.now().isoformat()
        
        return workflow_result
    
    def stop_agent(self, attack_id: str, agent_name: str) -> bool:
        """หยุด Agent ที่กำลังรัน"""
        key = f"{attack_id}_{agent_name}"
        
        if key in self.running_agents:
            agent = self.running_agents[key]
            
            # Try to stop agent
            if hasattr(agent, 'stop'):
                agent.stop()
            
            del self.running_agents[key]
            return True
        
        return False
    
    def get_running_agents(self) -> List[str]:
        """ดูรายการ Agents ที่กำลังรัน"""
        return list(self.running_agents.keys())


# Global agent executor instance
agent_executor = AgentExecutor()


def get_agent_executor() -> AgentExecutor:
    """Get global agent executor instance"""
    return agent_executor

