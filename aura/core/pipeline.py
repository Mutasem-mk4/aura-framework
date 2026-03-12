import time
import asyncio
from typing import List, Dict, Any, Type
from aura.core.context import MissionContext
from aura.core.metrics import METRICS

class PipelinePhase:
    """Base class for an execution phase in the Mission Pipeline."""
    name: str = "BasePhase"
    
    def __init__(self):
        pass
        
    async def execute(self, context: MissionContext, pipeline: 'MissionPipeline') -> Any:
        raise NotImplementedError("Phase must implement execute()")

class MissionPipeline:
    """
    Orchestrates the execution of distinct phases sequentially,
    passing the MissionContext between them. Replaces the "god object" 
    NeuralOrchestrator approach.
    """
    def __init__(self, context: MissionContext):
        self.context = context
        self.phases: List[PipelinePhase] = []
        self.state: Dict[str, Any] = {}
        
    def add_phase(self, phase: PipelinePhase):
        self.phases.append(phase)
        
    async def execute_all(self) -> Dict[str, Any]:
        """Runs all configured phases in order."""
        for phase in self.phases:
            _t0 = time.time()
            try:
                result = await phase.execute(self.context, self)
                # Store phase result in pipeline state for subsequent phases
                self.state[phase.name] = result
                
                # Observe metrics if available
                if hasattr(METRICS, 'phase_duration'):
                    METRICS.phase_duration.labels(phase_name=phase.name).observe(time.time() - _t0)
                    
            except Exception as e:
                import logging
                logging.getLogger("aura.pipeline").error(f"Phase {phase.name} failed: {e}")
                self.state["status"] = "ERROR"
                self.state["error"] = str(e)
                break
                
        self.state["status"] = self.state.get("status", "COMPLETE")
        return self.state
