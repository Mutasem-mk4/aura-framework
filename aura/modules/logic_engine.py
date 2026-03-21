"""
aura.modules.logic_engine

The Mission Strategist (Aura v2.0)
Transforms the AILogicEngine into the 'Brain' of the Event-Driven Ecosystem.
It monitors the EventBus, analyzes findings contextually, reprioritizes 
engines dynamically, and performs self-correction on engine failures.
"""

import asyncio
import json
from typing import List, Dict, Any, Optional
from rich.console import Console

from aura.core.engine_base import AbstractEngine
from aura.core.events import bus, EventType, AuraEvent
from aura.core.registry import get_registry

from aura.ui.formatter import console

class AILogicEngine(AbstractEngine):
    """
    The Mission Strategist: Monitors events, reprioritizes engines, 
    and coordinates the ecosystem like a Grandmaster playing chess.
    """
    ENGINE_ID = "ai_logic_engine"

    def __init__(self, persistence=None, telemetry=None, brain=None, **kwargs):
        super().__init__()
        self.persistence = persistence
        self.telemetry = telemetry
        self.brain = brain
        # Dynamic Priority Queue for Strategic Moves
        self.decision_queue = asyncio.PriorityQueue()

    async def setup(self, context):
        await super().setup(context)
        # Contextual Analysis: Monitor the EventBus in real-time
        bus.subscribe(EventType.VULNERABILITY_FOUND, self._on_finding)
        bus.subscribe(EventType.ERROR_OCCURRED, self._on_error)
        console.print("[bold magenta][🧠 Strategist] Neural Link established. Monitoring EventBus...[/bold magenta]")

    def _on_finding(self, event: AuraEvent):
        """Callback for real-time finding analysis."""
        finding_data = event.data
        finding_type = finding_data.get("type", "").lower()
        severity = finding_data.get("severity", "LOW").upper()
        
        # Calculate Dynamic Priority (lower number = higher priority)
        priority = 10
        if severity == "CRITICAL": priority = 1
        elif severity == "HIGH": priority = 3
        elif severity == "MEDIUM": priority = 5
        
        # Smart Decision Tree: Determine the next strategic move
        strategic_move = self._decision_matrix(finding_type)
        if strategic_move:
            console.print(f"[bold magenta][🧠 Strategist] High-value finding '{finding_type}'. Queuing move: {strategic_move} (Priority: {priority})[/bold magenta]")
            self.decision_queue.put_nowait((priority, strategic_move, finding_data))

    def _on_error(self, event: AuraEvent):
        """Self-Correction: Decides how to handle engine failures."""
        source_engine = event.source
        error_msg = event.message.lower()
        
        console.print(f"[bold yellow][🧠 Strategist] Engine {source_engine} faltered. Analyzing failure...[/bold yellow]")
        
        if "timeout" in error_msg or "waf" in error_msg or "blocked" in error_msg:
            # Self-Correction: Retry with different parameters (Stealth Mode)
            console.print(f"[bold yellow][🧠 Strategist] Signature blocked. Queuing stealth retry for {source_engine}.[/bold yellow]")
            self.decision_queue.put_nowait((2, "retry_stealth", {"engine": source_engine}))
        elif "connection" in error_msg or "offline" in error_msg:
            # Self-Correction: Skip and move to next
            console.print(f"[dim yellow][🧠 Strategist] Target appears offline. Skipping {source_engine} execution.[/dim yellow]")
        else:
            console.print(f"[dim yellow][🧠 Strategist] Unhandled error in {source_engine}. Logging telemetry.[/dim yellow]")

    def _decision_matrix(self, finding_type: str) -> List[str]:
        """
        Smart Decision Tree: Maps finding_type to specific 'Strategic Moves'.
        Returns a list of engine IDs to trigger.
        """
        if "subdomain" in finding_type:
            # High-value asset found -> Deep scan before PoC
            return ["banner_grabber", "aura_port_scanner", "threat_intel"]
        
        if "exposed_panel" in finding_type or "admin" in finding_type:
            # Admin panel found -> Fuzz logic and synthesize protocol attacks
            return ["protocol_synthesizer", "logic_fuzzer"]
        
        if "sql" in finding_type or "injection" in finding_type or "xss" in finding_type:
            # Potential injection -> Trigger deterministic verification
            return ["poc_engine", "exploit_chain"]
            
        if "secret" in finding_type or "leak" in finding_type or "token" in finding_type:
            # Hardcoded secret -> Go straight for the bounty report
            return ["bounty_hunter", "bounty_reporter"]
            
        return []

    async def run(self) -> List[Dict[str, Any]]:
        """
        Asynchronous Execution Flow:
        Processes the Dynamic Priority Queue and runs engines in parallel.
        """
        console.print("[bold magenta][🧠 Strategist] Executing Dynamic Priority Queue...[/bold magenta]")
        findings = []
        registry = get_registry()
        tasks = []
        
        # Drain the queue and execute strategies
        while not self.decision_queue.empty():
            priority, move, data = await self.decision_queue.get()
            
            kwargs = {
                "persistence": self.persistence, 
                "telemetry": self.telemetry, 
                "brain": self.brain
            }
            
            if move == "retry_stealth":
                engine_id = data.get("engine")
                console.print(f"[bold magenta][🧠 Strategist] Applying Self-Correction: Retrying {engine_id} with Jitter/Stealth...[/bold magenta]")
                
                # Mutate Context to force stealth
                self.context.flags.fast_mode = False 
                self.context.flags.ghost_mode = True
                
                # Re-run the specific engine
                tasks.append(registry.instantiate_and_run(engine_id, self.context, **kwargs))
                
            elif isinstance(move, list): 
                # Parallel execution of multiple engines
                console.print(f"[bold magenta][🧠 Strategist] Grandmaster Move: Parallel execution of {move}[/bold magenta]")
                tasks.append(registry.run_parallel(move, self.context, **kwargs))
                
            self.decision_queue.task_done()
            
        # Await all strategic moves simultaneously without blocking
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, list):
                    findings.extend(res)
                elif isinstance(res, dict):
                    findings.append(res)
                elif isinstance(res, Exception):
                    console.print(f"[bold red][🧠 Strategist] Strategy Execution Failed: {res}[/bold red]")
                    
        console.print(f"[bold green][🧠 Strategist] Strategic turn complete. Yielded {len(findings)} derived findings.[/bold green]")
        return findings

    async def teardown(self):
        """Cleanup subscriptions if needed."""
        pass
