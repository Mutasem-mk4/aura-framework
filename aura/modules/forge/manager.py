import os
import importlib.util
import inspect
import asyncio
from typing import List, Type
from aura.modules.forge.base import AuraPlugin

class ForgeManager:
    """Manages discovery and loading of Aura Forge plugins."""
    
    def __init__(self, plugins_dir: str = None):
        if plugins_dir is None:
            # Default to 'plugins' folder in the user's working directory
            plugins_dir = os.path.join(os.getcwd(), "plugins")
        
        self.plugins_dir = plugins_dir
        self.plugins: List[AuraPlugin] = []
        
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir)

    def load_plugins(self):
        """Discovers and instantiates plugins from the plugins directory."""
        self.plugins = []
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                filepath = os.path.join(self.plugins_dir, filename)
                plugin_instance = self._load_plugin_from_file(filepath)
                if plugin_instance:
                    self.plugins.append(plugin_instance)
        return self.plugins

    def _load_plugin_from_file(self, filepath: str) -> AuraPlugin:
        """Dynamically loads a class inheriting from AuraPlugin from a file."""
        module_name = os.path.basename(filepath)[:-3]
        spec = importlib.util.spec_from_file_location(module_name, filepath)
        module = importlib.util.module_from_spec(spec)
        
        try:
            spec.loader.exec_module(module)
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, AuraPlugin) and obj is not AuraPlugin:
                    return obj()
        except Exception as e:
            print(f"[!] Error loading plugin {filepath}: {e}")
        
        return None

    async def run_all(self, target: str, data: dict = None):
        """Executes all loaded plugins against a target."""
        results = {}
        for plugin in self.plugins:
            try:
                print(f"[*] Forge: Running {plugin.name} v{plugin.version}...")
                results[plugin.name] = await plugin.run(target, data)
            except Exception as e:
                print(f"[!] Forge: Plugin {plugin.name} failed: {e}")
        return results
