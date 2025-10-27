"""
Agent Manager Module
Manages agent lifecycle and execution
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import asyncio
import threading
import time
from core.logger import log
from core.agent_loader import AgentLoader


@dataclass
class AgentConfig:
    """Configuration for an agent"""
    name: str
    type: str
    enabled: bool = True
    max_concurrent: int = 1
    timeout: int = 300
    retry_count: int = 3


@dataclass
class AgentInstance:
    """Instance of a running agent"""
    id: str
    agent_class: Any
    config: AgentConfig
    status: str = "idle"
    last_activity: float = 0.0
    execution_count: int = 0


class AgentManager:
    """Manages agent lifecycle and execution"""

    def __init__(self):
        self.agents: Dict[str, AgentInstance] = {}
        self.agent_configs: Dict[str, AgentConfig] = {}
        self.loader = AgentLoader()
        self.running = False
        self._lock = threading.Lock()

    def load_agents(self, agents_dir: str = "agents") -> bool:
        """Load all agents from directory"""
        try:
            log.info(f"Loading agents from {agents_dir}")

            # Load agent modules
            modules = self.loader.load_all_agents(agents_dir)

            # Register agents from loaded modules
            for module_name, module in modules.items():
                if hasattr(module, 'Agent'):
                    agent_class = getattr(module, 'Agent')

                    # Create default config
                    config = AgentConfig(
                        name=getattr(agent_class, '__name__', module_name),
                        type=module_name
                    )

                    # Create agent instance
                    agent_instance = AgentInstance(
                        id=module_name,
                        agent_class=agent_class,
                        config=config
                    )

                    self.agents[module_name] = agent_instance
                    self.agent_configs[module_name] = config

            log.info(f"Successfully loaded {len(self.agents)} agents")
            return True

        except Exception as e:
            log.error(f"Failed to load agents: {e}")
            return False

    def get_agent(self, agent_id: str) -> Optional[AgentInstance]:
        """Get agent instance by ID"""
        return self.agents.get(agent_id)

    def get_all_agents(self) -> List[AgentInstance]:
        """Get all registered agents"""
        return list(self.agents.values())

    def start_agent(self, agent_id: str) -> bool:
        """Start an agent"""
        agent = self.get_agent(agent_id)
        if not agent:
            log.error(f"Agent not found: {agent_id}")
            return False

        with self._lock:
            if agent.status == "running":
                log.warning(f"Agent {agent_id} is already running")
                return False

            agent.status = "running"
            agent.last_activity = time.time()
            log.info(f"Started agent: {agent_id}")
            return True

    def stop_agent(self, agent_id: str) -> bool:
        """Stop an agent"""
        agent = self.get_agent(agent_id)
        if not agent:
            log.error(f"Agent not found: {agent_id}")
            return False

        with self._lock:
            if agent.status == "stopped":
                log.warning(f"Agent {agent_id} is already stopped")
                return False

            agent.status = "stopped"
            log.info(f"Stopped agent: {agent_id}")
            return True

    def execute_agent(self, agent_id: str, *args, **kwargs) -> Optional[Any]:
        """Execute an agent with given parameters"""
        agent = self.get_agent(agent_id)
        if not agent:
            log.error(f"Agent not found: {agent_id}")
            return None

        if agent.status != "running":
            log.error(f"Agent {agent_id} is not running")
            return None

        try:
            # Create agent instance
            agent_instance = agent.agent_class()

            # Execute the agent
            result = agent_instance.execute(*args, **kwargs)

            # Update execution count
            agent.execution_count += 1
            agent.last_activity = time.time()

            log.info(f"Agent {agent_id} executed successfully")
            return result

        except Exception as e:
            log.error(f"Agent {agent_id} execution failed: {e}")
            return None

    def get_agent_status(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get status of an agent"""
        agent = self.get_agent(agent_id)
        if not agent:
            return None

        return {
            "id": agent.id,
            "status": agent.status,
            "execution_count": agent.execution_count,
            "last_activity": agent.last_activity,
            "config": agent.config.__dict__
        }

    def get_all_agent_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all agents"""
        return {
            agent_id: self.get_agent_status(agent_id)
            for agent_id in self.agents.keys()
        }

    def reload_agent(self, agent_id: str) -> bool:
        """Reload an agent module"""
        agent = self.get_agent(agent_id)
        if not agent:
            log.error(f"Agent not found: {agent_id}")
            return False

        try:
            # Stop the agent first
            self.stop_agent(agent_id)

            # Reload the module
            module_name = agent.config.type
            success = self.loader.reload_agent(module_name)

            if success:
                log.info(f"Reloaded agent: {agent_id}")
                return True
            else:
                log.error(f"Failed to reload agent: {agent_id}")
                return False

        except Exception as e:
            log.error(f"Failed to reload agent {agent_id}: {e}")
            return False

    def start_all_agents(self) -> bool:
        """Start all agents"""
        try:
            for agent_id in self.agents.keys():
                self.start_agent(agent_id)
            log.info("Started all agents")
            return True
        except Exception as e:
            log.error(f"Failed to start all agents: {e}")
            return False

    def stop_all_agents(self) -> bool:
        """Stop all agents"""
        try:
            for agent_id in self.agents.keys():
                self.stop_agent(agent_id)
            log.info("Stopped all agents")
            return True
        except Exception as e:
            log.error(f"Failed to stop all agents: {e}")
            return False

    def cleanup(self):
        """Cleanup resources"""
        self.stop_all_agents()
        log.info("AgentManager cleanup completed")


# Example usage
if __name__ == "__main__":
    manager = AgentManager()
    success = manager.load_agents()
    if success:
        print(f"Loaded {len(manager.get_all_agents())} agents")
        print("AgentManager ready")
    else:
        print("Failed to load agents")