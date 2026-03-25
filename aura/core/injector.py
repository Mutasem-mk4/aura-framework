from __future__ import annotations

import inspect
from typing import Any

from aura.core.brain import AuraBrain
from aura.core.persistence import PersistenceHub
from aura.core.registry import get_registry
from aura.core.telemetry import Telemetry

class Container:
    """Dependency Injection Container for Aura Enterprise."""
    
    _instance: Container | None = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Container, cls).__new__(cls)
        return cls._instance

    def __init__(self, db_url: str | None = None) -> None:
        if hasattr(self, "_initialized"):
            return
        
        # Infrastructure
        self.persistence = PersistenceHub(db_url)
        self.telemetry = Telemetry(self.persistence)
        self.brain = AuraBrain()
        
        # Domain Services
        self.registry = get_registry()
        
        self._initialized = True

    def build_engine(self, engine_id: str, **overrides: Any) -> Any | None:
        """Instantiate a registered engine with only the dependencies it accepts."""
        engine_cls = self.registry.get_engine(engine_id)
        if engine_cls is None:
            return None

        dependencies: dict[str, Any] = {
            "persistence": self.persistence,
            "telemetry": self.telemetry,
            "brain": self.brain,
        }
        dependencies.update(overrides)

        try:
            signature = inspect.signature(engine_cls)
        except (TypeError, ValueError):
            return engine_cls(**dependencies)

        if any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        ):
            return engine_cls(**dependencies)

        accepted = {
            name: value
            for name, value in dependencies.items()
            if name in signature.parameters
        }
        return engine_cls(**accepted)

# Global Accessor (Optional, but useful for transition)
def get_container(db_url: str | None = None) -> Container:
    return Container(db_url)
