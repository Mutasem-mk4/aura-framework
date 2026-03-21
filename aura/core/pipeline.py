"""
aura.core.pipeline

Orchestrates the execution of distinct phases sequentially,
passing the MissionContext between them. Replaces the "god object" 
NeuralOrchestrator approach.
"""

import time
import asyncio
import logging
from typing import List, Dict, Any, Type
from aura.core.context import MissionContext
from aura.core.events import bus, AuraEvent, EventType
from aura.core.metrics import METRICS
from aura.ui.formatter import ZenithUI, console

logger = logging.getLogger("aura.pipeline")

class PipelinePhase:
    """Base class for an execution phase in the Mission Pipeline."""
    name: str = "BasePhase"
    
    def __init__(self):
        self.context: MissionContext = None
        
    async def setup(self, context: MissionContext):
        self.context = context
        
    async def execute(self, pipeline: 'MissionPipeline') -> Any:
        raise NotImplementedError("Phase must implement execute()")

class MissionPipeline:
    """
    Manages the sequential execution of Aura Phase Controllers.
    Passes the MissionContext through each phase and acts as the central event hub.
    """
    def __init__(self, context: MissionContext):
        self.context = context
        self.phases: List[Any] = []
        self.state: Dict[str, Any] = {
            "findings": [],
            "urls": []
        }
        
    def add_phase(self, phase: Any):
        """Registers a phase to be executed in the pipeline."""
        self.phases.append(phase)
        
    async def execute_all(self) -> Dict[str, Any]:
        """Runs all configured phases in order."""
        domain = self.context.target_url
        
        bus.publish(AuraEvent(
            type=EventType.PHASE_START,
            source="Pipeline",
            message=f"Mission Initiated: Target {domain}",
            data={"target": domain}
        ))
        
        console.print(f"[bold purple][[CROWN]] Decision: Primary Objective set to: {domain}[/bold purple]")
        
        with ZenithUI.status(f"Engaging Sentient Singularity for {domain}...") as status:
            for phase in self.phases:
                _t0 = time.time()
                
                # Dependency Injection of Context
                await phase.setup(self.context)
                
                try:
                    if phase.name == "ReconPhase":
                        result = await phase.run()
                        self.state["target_ip"] = result.get("target_ip")
                        self.state["intel_data"] = result.get("intel_data", {})
                        self.state["urls"] = [r.get("url") for r in result.get("urls", [])]
                    elif phase.name == "DeconstructionPhase":
                        result = await phase.run(self.state.get("recon_data", {}))
                        self.state["findings"].extend(result)
                    elif phase.name == "AuditPhase":
                        result = await phase.run(self.state.get("urls", []))
                        self.state["findings"].extend(result)
                    else:
                        result = await phase.run()
                        
                    # Store phase result in pipeline state for subsequent phases
                    self.state[phase.name] = result
                    
                    # Observe metrics if available
                    if hasattr(METRICS, 'phase_duration'):
                        METRICS.phase_duration.labels(phase_name=phase.name).observe(time.time() - _t0)
                        
                except Exception as e:
                    logger.error(f"Phase {phase.name} failed: {e}")
                    
                    bus.publish(AuraEvent(
                        type=EventType.ERROR_OCCURRED,
                        source="Pipeline",
                        message=f"Fatal Error in {phase.name}: {e}",
                        data={"phase": phase.name}
                    ))
                    
                    console.print(f"[bold red][ERR] Fatal Error in {phase.name}: {e}. Halting Pipeline.[/bold red]")
                    self.state["status"] = "ERROR"
                    self.state["error"] = str(e)
                    break
                    
        self.state["status"] = self.state.get("status", "COMPLETE")
        
        bus.publish(AuraEvent(
            type=EventType.PHASE_END,
            source="Pipeline",
            message=f"Mission Complete: {len(self.state['findings'])} findings."
        ))
        
        return self.state
