"""
Plugin Manager for Manus AI Platform
Manages plugin loading, validation, and execution in a secure environment
"""

import os
import json
import importlib
import importlib.util
from pathlib import Path
from typing import Dict, List, Any, Optional, Type
from core.logger import log
from core.plugin_sandbox import PluginSandbox


class PluginManifest:
    """Plugin manifest data structure"""
    def __init__(self, manifest_data: Dict[str, Any]):
        self.id = manifest_data.get('id', '')
        self.name = manifest_data.get('name', '')
        self.version = manifest_data.get('version', '1.0.0')
        self.description = manifest_data.get('description', '')
        self.type = manifest_data.get('type', 'custom')
        self.author = manifest_data.get('author', '')
        self.license = manifest_data.get('license', 'MIT')
        self.dependencies = manifest_data.get('dependencies', [])
        self.permissions = manifest_data.get('permissions', [])


class Plugin:
    """Plugin instance"""
    def __init__(self, manifest: PluginManifest, module_path: str):
        self.manifest = manifest
        self.module_path = module_path
        self.module = None
        self.is_loaded = False

    def load(self) -> bool:
        """Load plugin module"""
        try:
            spec = importlib.util.spec_from_file_location(
                self.manifest.id, self.module_path
            )
            if spec and spec.loader:
                self.module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(self.module)
                self.is_loaded = True
                log.info(f"Plugin '{self.manifest.name}' loaded successfully")
                return True
        except Exception as e:
            log.error(f"Failed to load plugin '{self.manifest.name}': {e}")
            return False

    def unload(self):
        """Unload plugin module"""
        if self.is_loaded and self.module:
            # Clear module from sys.modules
            import sys
            for name in list(sys.modules.keys()):
                if name.startswith(self.manifest.id):
                    del sys.modules[name]
            self.is_loaded = False
            log.info(f"Plugin '{self.manifest.name}' unloaded")


class PluginManager:
    """Plugin management system"""
    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.plugins: Dict[str, Plugin] = {}
        self.sandbox = PluginSandbox()
        self.is_initialized = False

    def initialize(self) -> bool:
        """Initialize plugin system"""
        try:
            # Create plugins directory if it doesn't exist
            self.plugins_dir.mkdir(exist_ok=True)

            # Load all available plugins
            self._discover_plugins()
            log.info(f"PluginManager initialized with {len(self.plugins)} plugins")
            self.is_initialized = True
            return True
        except Exception as e:
            log.error(f"Failed to initialize PluginManager: {e}")
            return False

    def _discover_plugins(self):
        """Discover and register plugins"""
        if not self.plugins_dir.exists():
            return

        # Look for plugin directories
        for plugin_path in self.plugins_dir.iterdir():
            if plugin_path.is_dir():
                manifest_path = plugin_path / "manifest.json"
                main_module_path = plugin_path / "main.py"

                if manifest_path.exists() and main_module_path.exists():
                    try:
                        # Load manifest
                        with open(manifest_path, 'r') as f:
                            manifest_data = json.load(f)

                        manifest = PluginManifest(manifest_data)

                        # Create plugin instance
                        plugin = Plugin(manifest, str(main_module_path))
                        self.plugins[manifest.id] = plugin

                        log.debug(f"Discovered plugin: {manifest.name}")

                    except Exception as e:
                        log.error(f"Failed to load plugin from {plugin_path}: {e}")

    def get_plugin(self, plugin_id: str) -> Optional[Plugin]:
        """Get plugin by ID"""
        return self.plugins.get(plugin_id)

    def load_plugin(self, plugin_id: str) -> bool:
        """Load a specific plugin"""
        plugin = self.get_plugin(plugin_id)
        if plugin:
            return plugin.load()
        return False

    def unload_plugin(self, plugin_id: str) -> bool:
        """Unload a specific plugin"""
        plugin = self.get_plugin(plugin_id)
        if plugin:
            plugin.unload()
            return True
        return False

    def load_all_plugins(self) -> List[str]:
        """Load all plugins"""
        loaded_plugins = []
        for plugin_id, plugin in self.plugins.items():
            if plugin.load():
                loaded_plugins.append(plugin_id)
        return loaded_plugins

    def unload_all_plugins(self):
        """Unload all plugins"""
        for plugin in self.plugins.values():
            plugin.unload()
        self.plugins.clear()

    def get_available_plugins(self) -> List[PluginManifest]:
        """Get list of available plugins"""
        return [plugin.manifest for plugin in self.plugins.values()]

    def execute_plugin_function(
        self, plugin_id: str, function_name: str, *args, **kwargs
    ) -> Any:
        """Execute a function from a plugin"""
        plugin = self.get_plugin(plugin_id)
        if not plugin or not plugin.is_loaded:
            raise ValueError(f"Plugin '{plugin_id}' not loaded")

        if not hasattr(plugin.module, function_name):
            raise AttributeError(f"Function '{function_name}' not found in plugin '{plugin_id}'")

        function = getattr(plugin.module, function_name)

        # Execute in sandbox for security
        return self.sandbox.run_in_sandbox(plugin.module, function_name, *args, **kwargs)

    def validate_plugin_permissions(self, plugin_id: str, required_permissions: List[str]) -> bool:
        """Validate plugin has required permissions"""
        plugin = self.get_plugin(plugin_id)
        if not plugin:
            return False

        plugin_permissions = set(plugin.manifest.permissions)
        required_permissions_set = set(required_permissions)

        return required_permissions_set.issubset(plugin_permissions)

    def get_plugin_dependencies(self, plugin_id: str) -> List[str]:
        """Get plugin dependencies"""
        plugin = self.get_plugin(plugin_id)
        if not plugin:
            return []

        return plugin.manifest.dependencies

    def __del__(self):
        """Cleanup on destruction"""
        if hasattr(self, 'plugins'):
            self.unload_all_plugins()


# Plugin development utilities
def create_plugin_template(plugin_name: str, plugins_dir: str = "plugins") -> bool:
    """Create a template for a new plugin"""
    plugins_path = Path(plugins_dir)
    plugin_path = plugins_path / plugin_name

    try:
        # Create plugin directory
        plugin_path.mkdir(parents=True, exist_ok=True)

        # Create manifest.json
        manifest_data = {
            "id": plugin_name.lower().replace(" ", "_"),
            "name": plugin_name,
            "version": "1.0.0",
            "description": f"A plugin for {plugin_name}",
            "type": "custom",
            "author": "Your Name",
            "license": "MIT",
            "dependencies": [],
            "permissions": []
        }

        with open(plugin_path / "manifest.json", 'w') as f:
            json.dump(manifest_data, f, indent=2)

        # Create main.py template
        main_py_content = f'''
"""
Plugin: {plugin_name}
Description: A plugin for Manus AI Platform
"""

def initialize():
    """Initialize the plugin"""
    print("Plugin {plugin_name} initialized")

def execute():
    """Main execution function"""
    print("Plugin {plugin_name} executed")

# Add your plugin functions here
'''

        with open(plugin_path / "main.py", 'w') as f:
            f.write(main_py_content)

        log.info(f"Plugin template created at {plugin_path}")
        return True

    except Exception as e:
        log.error(f"Failed to create plugin template: {e}")
        return False


# Example usage
if __name__ == "__main__":
    # Create plugin manager
    plugin_manager = PluginManager()

    # Initialize
    if plugin_manager.initialize():
        print(f"PluginManager initialized with {len(plugin_manager.plugins)} plugins")

        # Load all plugins
        loaded = plugin_manager.load_all_plugins()
        print(f"Loaded plugins: {loaded}")

        # List available plugins
        available_plugins = plugin_manager.get_available_plugins()
        for plugin in available_plugins:
            print(f"- {plugin.name} v{plugin.version}")