"""
Agent Loader Module
Loads and validates agent modules from the filesystem
"""

import importlib
import inspect
import os
import sys
from typing import Dict, Any, Type, Optional
from pathlib import Path
from core.logger import log


class AgentLoader:
    """Loads and validates agent modules"""

    def __init__(self):
        self.loaded_modules: Dict[str, Any] = {}

    def load_agent_module(self, module_path: str) -> Optional[Any]:
        """Load a single agent module"""
        try:
            # Convert file path to module path
            if module_path.endswith('.py'):
                module_path = module_path[:-3].replace('/', '.')

            log.info(f"Loading agent module: {module_path}")

            # Import the module
            module = importlib.import_module(module_path)

            # Validate the module has required components
            if not self._validate_agent_module(module):
                log.error(f"Invalid agent module: {module_path}")
                return None

            self.loaded_modules[module_path] = module
            log.info(f"Successfully loaded agent module: {module_path}")
            return module

        except Exception as e:
            log.error(f"Failed to load agent module {module_path}: {e}")
            return None

    def _validate_agent_module(self, module) -> bool:
        """Validate that a module contains required agent components"""
        required_classes = ['Agent']
        required_methods = ['execute']

        # Check for required classes
        for class_name in required_classes:
            if not hasattr(module, class_name):
                log.error(f"Missing required class: {class_name}")
                return False

        # Check for required methods in Agent class
        AgentClass = getattr(module, 'Agent')
        for method in required_methods:
            if not hasattr(AgentClass, method):
                log.error(f"Agent class missing required method: {method}")
                return False

        return True

    def load_all_agents(self, agents_dir: str = "agents") -> Dict[str, Any]:
        """Load all agent modules from a directory"""
        agents = {}

        if not os.path.exists(agents_dir):
            log.warning(f"Agents directory not found: {agents_dir}")
            return agents

        # Walk through the agents directory
        for root, dirs, files in os.walk(agents_dir):
            for file in files:
                if file.endswith('.py') and not file.startswith('__'):
                    # Get the relative module path
                    module_path = os.path.join(root, file)
                    relative_path = os.path.relpath(module_path, '.')

                    # Convert to module path
                    module_name = relative_path.replace('/', '.')[:-3]

                    # Load the module
                    module = self.load_agent_module(module_name)
                    if module:
                        agents[module_name] = module

        return agents

    def reload_agent(self, module_path: str) -> bool:
        """Reload a specific agent module"""
        try:
            if module_path in sys.modules:
                importlib.reload(sys.modules[module_path])
                log.info(f"Reloaded agent module: {module_path}")
                return True
            else:
                log.warning(f"Module not found in sys.modules: {module_path}")
                return False

        except Exception as e:
            log.error(f"Failed to reload agent module {module_path}: {e}")
            return False

    def get_loaded_modules(self) -> Dict[str, Any]:
        """Get all loaded modules"""
        return self.loaded_modules.copy()


# Example usage
if __name__ == "__main__":
    loader = AgentLoader()
    agents = loader.load_all_agents()
    print(f"Loaded {len(agents)} agent modules")