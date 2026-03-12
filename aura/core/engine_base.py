from typing import Any, Dict, List
from typing import Protocol, runtime_checkable
from aura.core.context import MissionContext

@runtime_checkable
class BaseEngine(Protocol):
    """
    Standard interface for all Aura vulnerability and discovery engines.
    """
    def setup(self, context: MissionContext) -> None:
        """Initialize the engine with the mission context."""
        ...

    async def run(self, target: str, **kwargs) -> Any:
        """Execute the engine's primary logic against the target."""
        ...

    async def teardown(self) -> None:
        """Cleanup resources, close sessions, etc."""
        ...

class AbstractEngine:
    """
    Base class implementation for Aura engines.
    """
    def __init__(self, context: MissionContext = None):
        self.context = context

    def setup(self, context: MissionContext) -> None:
        self.context = context

    async def run(self, target: str, **kwargs) -> Any:
        raise NotImplementedError("Engine must implement run()")

    async def teardown(self) -> None:
        pass
