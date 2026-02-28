# aura/plugins/base.py
from abc import ABC, abstractmethod

class AuraPlugin(ABC):
    """Base class for all Aura Forge plugins."""
    
    def __init__(self, name, version="1.0.0"):
        self.name = name
        self.version = version

    @abstractmethod
    async def run(self, target, context):
        """Main execution point for the plugin."""
        pass

    def log(self, message):
        from rich.console import Console
        console = Console()
        console.print(f"[bold magenta][Forge:{self.name}][/bold magenta] {message}")
