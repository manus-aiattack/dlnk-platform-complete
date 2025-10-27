from typing import Dict, Type, Any, Optional
from abc import ABC, abstractmethod
import importlib
import inspect
import os
import glob
from pathlib import Path
from core.logger import log
from core.plugin_manager import PluginManager


class AgentRegistry:
    def __init__(self):
        self.agents: Dict[str, Type] = {}
        self.agent_configs: Dict[str, Dict[str, Any]] = {}
        self.initialized_agents: Dict[str, Any] = {}
        self.plugin_manager = PluginManager("plugins")

        # Initialize plugin manager
        if not self.plugin_manager.initialize():
            log.warning("Failed to initialize PluginManager")

    def register_agent(self, name: str, agent_class: Type, config: Dict[str, Any] = None):
        """ลงทะเบียนเอเจนต์ใหม่"""
        self.agents[name] = agent_class
        self.agent_configs[name] = config or {}
        log.info(f"Registered agent: {name}")

    def auto_discover_agents(self, agents_dir: str = "agents", glob_func=glob.glob):
        """ค้นหาเอเจนต์อัตโนมัติจากโฟลเดอร์ agents และ plugins"""
        log.info(f"Discovering built-in agents from '{agents_dir}'...")
        # Adjust agents_dir to be relative to the project root
        project_root = Path(__file__).parent.parent
        absolute_agents_dir = project_root / agents_dir
        log.info(f"Searching for agents in: {absolute_agents_dir}")
        agent_files = glob_func(str(absolute_agents_dir / "**" / "*.py"), recursive=True)
        log.info(f"Discovered files: {agent_files}")
        for file_path in agent_files:
            try:
                # Convert file path to module path (e.g., agents/test/foo.py -> agents.test.foo)
                # Make module path relative to the project root for proper import
                relative_path = Path(file_path).relative_to(project_root)
                module_path = str(relative_path.with_suffix("")).replace(os.path.sep, ".")

                if '__init__' in module_path:
                    continue

                module = importlib.import_module(module_path)
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and hasattr(obj, 'run') and name.endswith('Agent') and name != "BaseAgent":
                        self.register_agent(name, obj)
            except Exception as e:
                log.error(f"Failed to discover agent in {file_path}: {e}")

        # Discover and load plugins
        self.plugin_manager.discover_and_load_plugins()

    def get_agent_class(self, name: str) -> Optional[Type]:
        """Retrieves an agent class by its name."""
        return self.agents.get(name)

    async def get_agent(self, name: str, context_manager=None, orchestrator=None) -> Any:
        """Creates, initializes, and returns an agent instance."""
        # Return cached instance if available
        if name in self.initialized_agents:
            return self.initialized_agents[name]

        if name not in self.agents:
            log.error(f"Attempted to get unregistered agent: {name}")
            raise ValueError(f"Agent {name} not registered")

        agent_class = self.agents[name]
        config = self.agent_configs.get(name, {})

        try:
            # Prepare arguments for agent instantiation
            init_kwargs = config.copy()
            sig_params = inspect.signature(agent_class.__init__).parameters

            if 'context_manager' in sig_params:
                init_kwargs['context_manager'] = context_manager
            if 'orchestrator' in sig_params:
                init_kwargs['orchestrator'] = orchestrator

            log.debug(f"Instantiating agent {name} with kwargs: {init_kwargs.keys()}")
            # Instantiate the agent
            agent_instance = agent_class(**init_kwargs)

            # Run asynchronous setup
            await agent_instance.setup()

            # Cache and return the initialized agent
            self.initialized_agents[name] = agent_instance
            log.info(f"Initialized and cached agent: {name}")
            return agent_instance

        except Exception as e:
            log.error(f"Failed to initialize agent {name}: {e}", exc_info=True)
            raise
