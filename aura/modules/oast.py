import logging
from aura.core.oast_server import OASTManager
from rich.console import Console

from aura.ui.formatter import console
logger = logging.getLogger("aura")

class OastCatcher:
    """v38.0: Bridge class for backward compatibility with existing modules."""
    def __init__(self):
        self.manager = OASTManager.get_instance()
        
    def setup(self):
        """Standard interface to get the base OAST URL."""
        # Note: initialize() is handled at orchestrator level in v38.0
        return self.manager.correlation_url

    def poll(self):
        """Polls for interactions (Now logic moved to background orchestrator loop)."""
        # In v38.0, we return the internal interaction buffer if needed, 
        # but the orchestrator handles the real reporting.
        return self.manager.interactions

    def get_payload(self, module_name: str, target_url: str) -> str:
        """Helper to get a unique payload for a sub-vulnerability."""
        return self.manager.get_payload(module_name, target_url)
