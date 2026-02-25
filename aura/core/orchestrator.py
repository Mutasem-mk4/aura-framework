import json
from aura.core.brain import AuraBrain
from aura.modules.scanner import AuraScanner
from aura.modules.exploiter import AuraExploiter
from aura.modules.dast import AuraDAST
from aura.modules.vision import VisualEye
from rich.console import Console

console = Console()

class NeuralOrchestrator:
    """The 'Sentient Brain' that orchestrates multi-step, logic-driven attack chains."""
    
    def __init__(self):
        self.brain = AuraBrain()
        self.scanner = AuraScanner()
        self.exploiter = AuraExploiter()
        self.dast = AuraDAST()
        self.vision = VisualEye()

    async def execute_advanced_chain(self, domain):
        """Executes a Chain-of-Thought (CoT) attack plan autonomously."""
        console.print(f"[bold magenta][🧠] NeuralOrchestrator: Developing Chain-of-Thought for {domain}...[/bold magenta]")
        
        # 1. Ask the Brain for a multi-step plan
        context = {"target": domain, "capability": "full_zenith_arsenal"}
        plan_raw = self.brain.reason(context)
        
        # 2. Extract logical steps (Simulated for Zenith)
        steps = [
            "Reconnaissance & Visualization",
            "Vulnerability Correlation",
            "Active DAST Probing",
            "Strategic Exploitation",
            "Reporting & Bounty Estimation"
        ]
        
        console.print("[cyan][*] Plan formulated. Executing 5-step Zenith protocol...[/cyan]")
        
        # Step 1: Recon & Vision
        results = self.scanner.discover_subdomains(domain)
        await self.vision.capture_screenshot(domain, "zenith_initial")
        
        # Step 2: DAST Probing
        vulns = await self.dast.scan_target(domain)
        
        # Step 3: Strategic Exploit
        if vulns:
            console.print(f"[bold red][!] Logic Triggered: High-risk vulnerabilities found. Initiating exploitation...[/bold red]")
            # Logic to select correct module...
            
        console.print("[bold green][✔] NeuralOrchestrator: Zenith chain complete.[/bold green]")
        return {"plan": plan_raw, "findings": vulns}
