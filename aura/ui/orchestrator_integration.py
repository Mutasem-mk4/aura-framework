"""
Aura Orchestrator Integration Example
======================================
Shows how to wrap NeuralOrchestrator with ZenithFormatter UI.

Usage:
    from aura.ui.formatter import OrchestratorUI, logger
    
    # In your main.py or cli.py:
    orchestrator = NeuralOrchestrator(...)
    ui = OrchestratorUI()
    
    # Wrap initialization display
    ui.wrap_initialization({
        "scanner": orchestrator.scanner,
        "nexus_bridge": orchestrator.nexus_bridge,
        "power_stack": orchestrator.power_stack,
        # ... other engines
    })
"""

import asyncio
from aura.ui.formatter import ZenithFormatter, ZenithLogger, OrchestratorUI, logger
from aura.core.orchestrator import NeuralOrchestrator
from aura.core.injector import get_container


async def run_mission_with_ui(target: str):
    """
    Run a mission with full Zenith UI styling.
    """
    formatter = ZenithFormatter()
    ui_logger = ZenithLogger()
    
    # 1. Show Banner
    formatter.show_banner()
    
    # 2. Initialize Orchestrator
    ui_logger.info(f"Initializing NeuralOrchestrator for {target}...")
    
    container = get_container()
    orchestrator = NeuralOrchestrator(container=container)
    
    # 3. Show Engine Status Table
    engines = {
        "aura_scanner": orchestrator.scanner,
        "aura_exploiter": orchestrator.exploiter,
        "aura_dast": orchestrator.dast,
        "aura_singularity": orchestrator.singularity,
        "nexus_bridge": orchestrator.nexus_bridge,
        "burp_bridge": orchestrator.burp_bridge,
        "power_stack": orchestrator.power_stack,
        "recon_pipeline": orchestrator.recon_pipeline,
    }
    
    formatter.show_engine_table([
        {"name": name, "status": "loaded", "provider": getattr(engine, '__module__', 'unknown')}
        for name, engine in engines.items()
    ])
    
    # 4. Mission Phases with Progress
    ui_logger.header(f"Starting Mission: {target}")
    
    # Phase 1: Recon
    formatter.phase_banner("Phase 1: Intelligence Gathering", target)
    
    with formatter.create_progress() as progress:
        task = progress.add_task("[cyan]Reconnaissance", total=100)
        
        # Simulate work
        progress.update(task, advance=30, description="[cyan]Enumerating subdomains...")
        await asyncio.sleep(0.5)
        
        progress.update(task, advance=30, description="[cyan]Checking OSINT...")
        await asyncio.sleep(0.5)
        
        progress.update(task, advance=40, description="[green]Discovery complete")
    
    ui_logger.success(f"Found 15 subdomains for {target}")
    
    # Phase 2: Discovery
    formatter.phase_banner("Phase 2: Deep Discovery", target)
    
    with formatter.create_progress() as progress:
        task = progress.add_task("[cyan]Spidering", total=100)
        
        for i in range(10):
            progress.update(task, advance=10, description=f"[cyan]Crawling page {i+1}/10")
            await asyncio.sleep(0.2)
    
    ui_logger.success("Spidering complete: 150 endpoints discovered")
    
    # Phase 3: Audit
    formatter.phase_banner("Phase 3: Vulnerability Assessment", target)
    
    # Simulate findings
    findings = [
        {"type": "SQL Injection", "severity": "critical", "target_value": target},
        {"type": "XSS Reflected", "severity": "high", "target_value": target},
        {"type": "Information Disclosure", "severity": "medium", "target_value": target},
    ]
    
    for finding in findings:
        formatter.show_finding(
            vuln_type=finding["type"],
            severity=finding["severity"],
            target=finding["target_value"]
        )
        ui_logger.info(f"Finding saved: {finding['type']}")
    
    # Summary
    ui_logger.header("Mission Complete")
    ui_logger.success(f"Scan complete: {len(findings)} vulnerabilities found")
    ui_logger.info(f"Results saved to: aura_intel.db")
    
    # Cleanup
    await orchestrator.close()


if __name__ == "__main__":
    asyncio.run(run_mission_with_ui("example.com"))
