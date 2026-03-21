from typing import Any, Dict, Optional
from aura.core.persistence import PersistenceHub
from aura.core.registry import EngineRegistry
from aura.core.telemetry import Telemetry

class Container:
    """Dependency Injection Container for Aura Enterprise."""
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Container, cls).__new__(cls)
        return cls._instance

    def __init__(self, db_url: Optional[str] = None):
        if hasattr(self, '_initialized'): return
        
        # Infrastructure
        self.persistence = PersistenceHub(db_url)
        self.telemetry = Telemetry(self.persistence)
        
        # Domain Services
        self.registry = EngineRegistry()
        self.registry.discover()
        
        self._initialized = True

# Global Accessor (Optional, but useful for transition)
def get_container(db_url: Optional[str] = None) -> Container:
    return Container(db_url)
