import asyncio
from rich.console import Console

console = Console()

class NeuralForge:
    """
    v19.0 THE SINGULARITY
    Neural-Forge - Zero-Day Logic Synthesis Engine.
    """
    def __init__(self, brain):
        self.brain = brain
        self.synthesized_vectors = []

    async def synthesize_0day_vectors(self, state_machine: dict, tech_stack: list):
        """AI analyzes the state machine to forge unique tactical vectors."""
        console.print("[bold magenta][🧠] Neural-Forge: Initiating Deep Logic Synthesis...[/bold magenta]")
        
        # Analyze state-machine nodes to find 'Atomic Transitions' that can be broken
        prompt = (
            f"As AURA Singularity Neural-Forge, analyze this application state machine: {state_machine}\n"
            f"Tech Stack: {tech_stack}\n"
            "Identify 3 unique 'Logic 0-Day' vectors. Focus on:\n"
            "1. Race Conditions in state transitions (e.g., cancel vs. confirm).\n"
            "2. Atomic collision vulnerabilities.\n"
            "3. Multi-step session synchronization errors.\n"
            "Respond ONLY in JSON: [{'name': 'str', 'logic': 'str', 'lethality': 'HIGH/CRITICAL'}]"
        )
        try:
            vectors = self.brain.reason_json(prompt)
            import json
            self.synthesized_vectors = json.loads(vectors)
            
            for v in self.synthesized_vectors:
                console.print(f"[bold red][⚓] Synthesized 0-Day Forge: {v['name']} (Lethality: {v['lethality']})[/bold red]")
                console.print(f"[dim]Logic: {v['logic']}[/dim]")
            
            return self.synthesized_vectors
        except Exception as e:
            console.print(f"[red][!] Neural-Forge Synthesis Error: {e}[/red]")
            return []

    def get_forge_report(self):
        """Generates a technical summary of synthesized logic flaws."""
        report = "### Neural-Forge 0-Day Logic Vectors\n"
        for v in self.synthesized_vectors:
            report += f"- **{v['name']}**: {v['logic']}\n"
        return report
