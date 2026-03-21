"""
aura.core.errors

Centralized Error Manager to eliminate scattered try/except blocks.
Standardizes how exceptions are caught, logged, and recovered from.
"""

from typing import Optional, Any
from pydantic import BaseModel
from aura.core.events import bus, AuraEvent, EventType

class AuraException(Exception):
    """Base exception class for all custom Aura errors."""
    def __init__(self, message: str, severity: str = "ERROR", source: str = "SYSTEM"):
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.source = source


class NetworkTimeoutError(AuraException):
    """Raised when an HTTP request times out against the target."""
    def __init__(self, message: str, source: str):
        super().__init__(message, severity="WARNING", source=source)


class ConfigurationError(AuraException):
    """Raised when the MissionContext lacks required API keys or valid configs."""
    def __init__(self, message: str):
        super().__init__(message, severity="CRITICAL", source="CONFIG")


class TargetOfflineError(AuraException):
    """Raised when the target fails DNS resolution or is completely unreachable."""
    def __init__(self, message: str):
        super().__init__(message, severity="CRITICAL", source="NETWORK")


class ErrorManager:
    """
    Central handler for exceptions. Emits error events and decides
    if the pipeline should halt based on severity.
    """
    
    @staticmethod
    def handle(e: Exception, source: str, context: Optional[Any] = None) -> bool:
        """
        Log the exception and dispatch an event.
        Returns True if execution can continue, False if the error is fatal.
        """
        severity = "ERROR"
        message = str(e)
        
        if isinstance(e, AuraException):
            severity = e.severity
            source = e.source
            
        # Dispatch event to the UI/Logging layer
        bus.publish(AuraEvent(
            type=EventType.ERROR_OCCURRED,
            source=source,
            message=message,
            data={"severity": severity, "type": e.__class__.__name__}
        ))
        
        # Determine if fatal
        if severity == "CRITICAL" or isinstance(e, TargetOfflineError):
            return False  # Fatal, Pipeline must halt
            
        return True # Soft error, skip and continue
