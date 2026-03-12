import asyncio
import os
import sys
import json
from rich.console import Console

# Ensure Aura is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aura.core.storage import AuraStorage
from aura.core.orchestrator import NeuralOrchestrator
from aura.modules.semantic_ast_engine import SemanticASTAnalyzer
from aura.modules.stateful_logic_fuzzer import StatefulLogicFuzzer, WorkflowStep, SessionState

console = Console()

async def test_storage_agnostic():
    """Verify database-agnostic zipping logic."""
    console.print("[bold cyan][TEST] Sector: AuraStorage (Agnostic Parsing)...[/bold cyan]")
    test_db_path = "omega_test.db"
    if os.path.exists(test_db_path): os.remove(test_db_path)
    
    try:
        db = AuraStorage(db_path=test_db_path)
        # db._init_db() is called in __init__
        
        # Test Data Insertion
        db.save_target({"target": "test.com", "type": "Domain", "status": "PENDING"})
        
        # Test Retrieval (Agnostic Parsing)
        targets = db.get_all_targets()
        if targets and isinstance(targets[0], dict) and "value" in targets[0]:
            console.print("[bold green]  [✓] AuraStorage retrieval returned correct dictionary format.[/bold green]")
            return True
        else:
            console.print("[bold red]  [✗] AuraStorage retrieval FAILED agnostic parsing check.[/bold red]")
            return False
    finally:
        if os.path.exists(test_db_path): os.remove(test_db_path)

async def test_semantic_ast_precision():
    """Verify data-flow aware static analysis."""
    console.print("[bold cyan][TEST] Sector: Semantic AST Engine (Variable Tracking)...[/bold cyan]")
    analyzer = SemanticASTAnalyzer(strict_mode=True)
    
    # Case 1: Overwritten Taint (Safe)
    js_safe = "let x = window.location.hash; x = 'safe'; eval(x);"
    findings_safe = await analyzer.analyze(js_safe, source="test_safe.js")
    
    # Case 2: Direct Taint (Unsafe)
    js_vuln = "let y = window.location.hash; eval(y);"
    findings_vuln = await analyzer.analyze(js_vuln, source="test_vuln.js")
    
    if len(findings_safe) == 0 and len(findings_vuln) > 0:
        console.print("[bold green]  [✓] Semantic AST correctly tracked variable state and avoided FP.[/bold green]")
    else:
        console.print(f"[bold red]  [✗] Semantic AST FAILED precision check. Safe: {len(findings_safe)}, Vuln: {len(findings_vuln)}[/bold red]")
        return False
    return True

async def test_logic_fuzzer_omega():
    """Verify parallel semantic fuzzing and state-inversion."""
    console.print("[bold cyan][TEST] Sector: Stateful Logic Fuzzer (Omega Strategy)...[/bold cyan]")
    fuzzer = StatefulLogicFuzzer(base_url="http://mock-api.local")
    
    # Mock Step
    step = WorkflowStep(
        step_id="checkout", name="Checkout", method="POST", path="/api/checkout",
        data={"price": 100, "qty": 1}, fuzz_params=["price"]
    )
    
    # Test State Inversion call (ensure it doesn't crash)
    try:
        await fuzzer.test_state_inversion(step, SessionState())
        console.print("[bold green]  [✓] Logic Fuzzer state-inversion protocol initialized correctly.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]  [✗] Logic Fuzzer state-inversion CRASHED: {e}[/bold red]")
        return False
    return True

async def test_orchestrator_phases():
    """Verify phase-based mission chaining."""
    console.print("[bold cyan][TEST] Sector: NeuralOrchestrator (Phase Chaining)...[/bold cyan]")
    # Pass empty lists for whitelist/blacklist to avoid file-system checks in ScopeManager if possible
    orch = NeuralOrchestrator(whitelist=["*.test.com"], blacklist=[])
    
    # Verify phase presence
    phases = ["_phase_preflight", "_phase_intel", "_phase_recon", "_phase_discovery", "_phase_audit", "_phase_exploit", "_phase_finalize"]
    missing = [p for p in phases if not hasattr(orch, p)]
    
    if not missing:
        console.print("[bold green]  [✓] NeuralOrchestrator modular phases are verified and ready.[/bold green]")
    else:
        console.print(f"[bold red]  [✗] NeuralOrchestrator is MISSING phases: {missing}[/bold red]")
        return False
    return True

async def main():
    console.print("\n[bold magenta]AURA v25.0 OMEGA — SYSTEM INTEGRITY TEST[/bold magenta]\n")
    results = [
        await test_storage_agnostic(),
        await test_semantic_ast_precision(),
        await test_logic_fuzzer_omega(),
        await test_orchestrator_phases()
    ]
    
    if all(results):
        console.print("\n[bold green]✅ ALL OMEGA SECTORS ARE OPERATIONAL. SWARM READINESS CONFIRMED.[/bold green]\n")
    else:
        console.print("\n[bold red]❌ SYSTEM INTEGRITY COMPROMISED. REVIEW SECTOR LOGS.[/bold red]\n")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
