"""
Agent Registry Service
จัดการและลงทะเบียน Attack Agents ทั้งหมดในระบบ
"""

import os
import sys
import importlib
import inspect
from typing import Dict, List, Any, Optional, Type
from pathlib import Path


class AgentRegistry:
    """Registry สำหรับจัดการ Attack Agents ทั้งหมด"""
    
    def __init__(self, agents_dir: str = None):
        if agents_dir is None:
            # Default to agents directory
            current_dir = Path(__file__).parent.parent.parent
            agents_dir = str(current_dir / "agents")
        
        self.agents_dir = agents_dir
        self.agents: Dict[str, Type] = {}
        self.agent_metadata: Dict[str, Dict[str, Any]] = {}
        
        # Add agents directory to Python path
        if agents_dir not in sys.path:
            sys.path.insert(0, str(Path(agents_dir).parent))
    
    def discover_agents(self) -> int:
        """ค้นหาและลงทะเบียน Agents ทั้งหมดอัตโนมัติ"""
        count = 0
        
        # Walk through agents directory
        for root, dirs, files in os.walk(self.agents_dir):
            for file in files:
                if file.endswith('_agent.py') or file.endswith('_exploiter.py'):
                    filepath = os.path.join(root, file)
                    count += self._load_agent_from_file(filepath)
        
        return count
    
    def _load_agent_from_file(self, filepath: str) -> int:
        """โหลด Agent จากไฟล์"""
        try:
            # Get module name from filepath
            rel_path = os.path.relpath(filepath, str(Path(self.agents_dir).parent))
            module_name = rel_path.replace(os.sep, '.').replace('.py', '')
            
            # Import module
            module = importlib.import_module(module_name)
            
            # Find agent classes
            count = 0
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # Check if it's an agent class (not base class)
                if (name.endswith('Agent') or name.endswith('Exploiter')) and \
                   obj.__module__ == module.__name__:
                    self.register_agent(name, obj)
                    count += 1
            
            return count
            
        except Exception as e:
            print(f"Error loading agent from {filepath}: {e}")
            return 0
    
    def register_agent(self, name: str, agent_class: Type, metadata: Dict[str, Any] = None):
        """ลงทะเบียน Agent"""
        self.agents[name] = agent_class
        
        # Extract metadata from agent class
        if metadata is None:
            metadata = self._extract_metadata(agent_class)
        
        self.agent_metadata[name] = metadata
    
    def _extract_metadata(self, agent_class: Type) -> Dict[str, Any]:
        """ดึง metadata จาก Agent class"""
        metadata = {
            "name": agent_class.__name__,
            "module": agent_class.__module__,
            "description": agent_class.__doc__ or "No description",
            "methods": []
        }
        
        # Get methods
        for name, method in inspect.getmembers(agent_class, inspect.isfunction):
            if not name.startswith('_'):
                metadata["methods"].append(name)
        
        # Try to get additional metadata from class attributes
        if hasattr(agent_class, 'AGENT_TYPE'):
            metadata["type"] = agent_class.AGENT_TYPE
        if hasattr(agent_class, 'SEVERITY'):
            metadata["severity"] = agent_class.SEVERITY
        if hasattr(agent_class, 'REQUIRES'):
            metadata["requires"] = agent_class.REQUIRES
        
        return metadata
    
    def get_agent(self, name: str) -> Optional[Type]:
        """ดึง Agent class ตามชื่อ"""
        return self.agents.get(name)
    
    def get_agent_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        """ดึง metadata ของ Agent"""
        return self.agent_metadata.get(name)
    
    def list_agents(self) -> List[str]:
        """แสดงรายชื่อ Agents ทั้งหมด"""
        return list(self.agents.keys())
    
    def list_agents_by_type(self, agent_type: str) -> List[str]:
        """แสดงรายชื่อ Agents ตาม type"""
        return [
            name for name, metadata in self.agent_metadata.items()
            if metadata.get("type") == agent_type
        ]
    
    def get_all_metadata(self) -> Dict[str, Dict[str, Any]]:
        """ดึง metadata ของ Agents ทั้งหมด"""
        return self.agent_metadata
    
    def instantiate_agent(self, name: str, *args, **kwargs):
        """สร้าง instance ของ Agent"""
        agent_class = self.get_agent(name)
        if agent_class is None:
            raise ValueError(f"Agent '{name}' not found in registry")
        
        return agent_class(*args, **kwargs)


# Global agent registry instance
agent_registry = AgentRegistry()


def init_agent_registry() -> int:
    """Initialize agent registry"""
    count = agent_registry.discover_agents()
    print(f"Discovered {count} agents")
    return count


def get_agent_registry() -> AgentRegistry:
    """Get global agent registry instance"""
    return agent_registry

