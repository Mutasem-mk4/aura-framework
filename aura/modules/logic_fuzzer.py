import os
import asyncio
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Union
from rich.console import Console
from aura.core.engine_interface import IEngine
from aura.core.models import Finding, Severity
from aura.core.brain import AuraBrain
from aura.modules.stateful_logic_fuzzer import StatefulLogicFuzzer, run_logic_fuzz, Vulnerability

from aura.ui.formatter import console

class LogicFuzzer(IEngine):
    """
    v38.0 Logic Hunter: High-level wrapper for stateful business logic fuzzing.
    Integrates with the NeuralOrchestrator and uses the StatefulLogicFuzzer.
    """
    
    ENGINE_ID = "logic_fuzzer"

    def __init__(self, brain=None, stealth=None, persistence=None, telemetry=None, **kwargs):
        self.brain = brain or AuraBrain()
        self.stealth = stealth
        self.persistence = persistence
        self.telemetry = telemetry
        self._status = "initialized"

    async def run(self, target: str, **kwargs) -> List[Finding]:
        """
        Executes the logic fuzzer against the target.
        
        Args:
            target: Target URL
            **kwargs: Can include 'workflow_json' or 'workflow_path'
            
        Returns:
            List of Finding objects
        """
        self._status = "running"
        workflow_json = kwargs.get("workflow_json")
        workflow_path = kwargs.get("workflow_path")
        
        console.print(f"[bold cyan]🔍 [LogicFuzzer] Starting stateful logic audit on {target}...[/bold cyan]")
        
        # findings_raw will be a list of Vulnerability or Dict objects from StatefulLogicFuzzer
        try:
            findings_raw = await run_logic_fuzz(
                target=target, 
                workflow_path=workflow_path, 
                workflow_json=workflow_json
            )
        except Exception as e:
            console.print(f"[bold red]❌ [LogicFuzzer] Error during execution: {e}[/bold red]")
            self._status = "failed"
            return []
        
        # Convert raw findings to Aura Finding objects
        findings = []
        for v in findings_raw:
            if isinstance(v, Vulnerability):
                v_type = v.vuln_type
                v_severity = v.severity
                v_desc = v.description
                v_evidence = v.evidence
                v_rem = v.remediation
                v_cwe = v.cwe_id
                v_step = v.step_id
            else:
                # Handle Dict fallback
                v_type = v.get("type", "Logic Flaw")
                v_severity = v.get("severity", "MEDIUM")
                v_desc = v.get("description", "Unknown business logic anomaly detected.")
                v_evidence = v.get("evidence", {})
                v_rem = v.get("remediation", "")
                v_cwe = v.get("cwe_id", "")
                v_step = v.get("step_id", "unknown")

            finding = Finding(
                target_value=target,
                content=f"{v_type}: {v_desc}",
                finding_type="Business Logic Flaw",
                severity=getattr(Severity, v_severity.upper(), Severity.MEDIUM),
                proof=json.dumps(v_evidence),
                meta={
                    "remediation": v_rem,
                    "cwe": v_cwe,
                    "step_id": v_step,
                    "engine": self.ENGINE_ID
                }
            )
            findings.append(finding)
            
            # Log to persistence if available
            if self.persistence:
                try:
                    self.persistence.add_finding(finding.model_dump())
                except Exception as ex:
                    console.print(f"[dim red][!] Failed to persist logic finding: {ex}[/dim red]")
                
        self._status = "completed"
        return findings

    def get_status(self) -> Dict[str, Any]:
        return {"id": self.ENGINE_ID, "status": self._status}

if __name__ == "__main__":
    # Standard CLI wrapper if run directly
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="Aura Logic Fuzzer")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--workflow", help="Path to workflow JSON")
    args = parser.parse_args()
    
    async def main():
        fuzzer = LogicFuzzer()
        results = await fuzzer.run(args.target, workflow_path=args.workflow)
        console.print(f"\n[bold green][✓] Audit Complete. Found {len(results)} vulnerabilities.[/bold green]")
        
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
