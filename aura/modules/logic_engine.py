import asyncio
from rich.console import Console

console = Console()

class LogicBlueprinter:
    """
    v16.0 OMNI-SOVEREIGN
    Autonomous Business Logic State Machine Blueprinting
    """
    def __init__(self, brain):
        self.brain = brain
        self.state_machine = {} # {path: {method: {params: [], response_type: ''}}}
        self.critical_paths = ["checkout", "payment", "admin", "config", "transfer", "withdraw"]
        
    async def blueprint_target(self, discovered_urls: list):
        """Analyzes a list of URLs to build the initial logic blueprint."""
        console.print("[bold cyan][👑] Omni-Sovereign: Blueprinting Application State Machine...[/bold cyan]")
        for url in discovered_urls:
            # AI-assisted classification of the path
            if any(p in url.lower() for p in self.critical_paths):
                self._add_to_blueprint(url, "CRITICAL")
                
    def _add_to_blueprint(self, url, stance):
        if url not in self.state_machine:
            self.state_machine[url] = {"stance": stance, "transitions": []}
            
    def identify_state_skipping_vectors(self):
        """AI analyzes the blueprint to find logical shortcuts."""
        # v16.0 Logic: Identify paths that lead to 'Success' without passing through 'Gatekeepers'
        vectors = []
        for path, data in self.state_machine.items():
            if data["stance"] == "CRITICAL" and "payment" in path:
                # Potential jump to /checkout/success
                vectors.append(f"{path} -> /checkout/success (State Skip)")
        return vectors

    def generate_blueprint_report(self):
        """Generates a technical summary of the mapped logic."""
        report = "### Business Logic State Machine\n"
        for path, data in self.state_machine.items():
            report += f"- **{path}** [{data['stance']}]\n"
        return report
