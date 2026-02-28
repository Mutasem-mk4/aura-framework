from abc import ABC, abstractmethod

class AuraPlugin(ABC):
    """Base class for all Aura Forge plugins."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """The name of the plugin."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """A brief description of what the plugin does."""
        pass

    @property
    def version(self) -> str:
        """The version of the plugin."""
        return "1.0.0"

    @abstractmethod
    async def run(self, target: str, data: dict = None) -> dict:
        """
        The main execution logic for the plugin.
        
        :param target: The target domain or IP.
        :param data: Optional metadata or previous results.
        :return: A dictionary of findings.
        """
        pass
