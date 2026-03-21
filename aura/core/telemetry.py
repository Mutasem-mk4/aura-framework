import logging
import time
from typing import Dict, Any, Optional
from rich.console import Console

from aura.ui.formatter import console

class Telemetry:
    """
    Centralized Telemetry Service for Aura Phase 3.
    Handles audit logs, error tracking, and performance metrics.
    """
    def __init__(self, persistence=None):
        self.persistence = persistence
        self.logger = logging.getLogger("aura.telemetry")
        self._start_time = time.time()
        self.metrics = {
            "findings_count": 0,
            "engines_started": 0,
            "errors_encountered": 0,
            "total_scan_duration": 0
        }

    def log_audit(self, target: str, action: str, details: str = ""):
        """Standardized audit logging."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        msg = f"[{timestamp}] {action} on {target}: {details}"
        self.logger.info(msg)
        
        if self.persistence:
            self.persistence.log_audit(target, f"{action}: {details}")

    def log_error(self, engine_id: str, error_msg: str, trace: Optional[str] = None):
        """Standardized error tracking."""
        self.metrics["errors_encountered"] += 1
        self.logger.error(f"ENGINE_ERROR [{engine_id}]: {error_msg}")
        if trace:
            self.logger.error(f"TRACE: {trace}")
        
        if self.persistence:
            # Assuming persistence has an error log repository or similar
            self.persistence.log_audit("SYSTEM", f"ERROR_{engine_id}: {error_msg}")

    def update_metric(self, name: str, value: Any):
        """Update a specific telemetry metric."""
        if name in self.metrics:
            if isinstance(value, (int, float)) and isinstance(self.metrics[name], (int, float)):
                self.metrics[name] += value
            else:
                self.metrics[name] = value

    def get_summary(self) -> Dict[str, Any]:
        """Returns a snapshot of the current scan telemetry."""
        self.metrics["total_scan_duration"] = time.time() - self._start_time
        return self.metrics
