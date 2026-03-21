from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from aura.core.models import Finding

class IEngine(ABC):
    """
    Standard interface for all Aura Security Engines.
    Every engine must implement 'run' and provide its unique ID.
    """
    
    ENGINE_ID: str = "base_engine"

    @abstractmethod
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """
        Main execution entry point for the engine.
        Should return a list of Domain Findings.
        """
        pass

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Returns the current operational status of the engine."""
        pass
