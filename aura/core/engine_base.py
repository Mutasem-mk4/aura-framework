"""
aura.core.engine_base

Defines the strict interfaces (Protocols/ABCs) that all vulnerability, 
OSINT, and enumeration engines must implement.

Enables dynamic loading via the Mission Pipeline.
"""

from typing import Any, Dict, Protocol, runtime_checkable, Optional
from aura.core.context import MissionContext
from aura.core.events import bus, AuraEvent, EventType
from aura.core.errors import ErrorManager

@runtime_checkable
class BaseEngine(Protocol):
    """
    Standard interface for all Aura vulnerability and discovery engines.
    """
    async def setup(self, context: MissionContext) -> None:
        """Initialize the engine with the mission context."""
        ...

    async def run(self) -> Any:
        """Execute the engine's primary logic against the target in context."""
        ...

    async def teardown(self) -> None:
        """Cleanup resources, close sessions, etc."""
        ...


class AbstractEngine:
    """
    Base class implementation for Aura engines.
    Provides standard error handling and event emission.
    """
    def __init__(self):
        self.context: Optional[MissionContext] = None
        self.name: str = self.__class__.__name__

    async def setup(self, context: MissionContext) -> None:
        """Saves the context and performs base setup."""
        self.context = context
        # Provide base event logging for engine initialization
        bus.publish(AuraEvent(
            type=EventType.SYSTEM_LOG,
            source=self.name,
            message=f"Engine initialized for target {self.context.target_url}"
        ))

    async def run(self) -> Any:
        """Must be implemented by child classes."""
        raise NotImplementedError("Engine must implement run()")

    async def teardown(self) -> None:
        """Optional cleanup routine."""
        pass
        
    def _emit_progress(self, message: str, percentage: int = 0):
        """Helper to safely emit progress back to the UI/Pipeline."""
        bus.publish(AuraEvent(
            type=EventType.PROGRESS_UPDATE,
            source=self.name,
            message=message,
            data={"percentage": percentage}
        ))
        
    def _emit_vuln(self, vulnerability: Dict[str, Any]):
        """Helper to register a found vulnerability via the Event Bus."""
        bus.publish(AuraEvent(
            type=EventType.VULNERABILITY_FOUND,
            source=self.name,
            message=f"Detected: {vulnerability.get('type', 'Unknown Vulnerability')}",
            data=vulnerability
        ))
        # Safely add to context for reporting if context exists
        if self.context:
            self.context.vulnerabilities.append(vulnerability)

    def _handle_error(self, e: Exception) -> bool:
        """Helper to pass errors to the central Error Manager."""
        return ErrorManager.handle(e, source=self.name, context=self.context)
