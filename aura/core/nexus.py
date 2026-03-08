import cmd
import asyncio
from rich.console import Console
from rich.table import Table

console = Console()

class NexusShell(cmd.Cmd):
    """v16.1: Nexus War Room - Interactive AI C2 Interface."""
    intro = '[bold cyan]👑 AURA-ZENITH NEXUS WAR ROOM (v16.1) Initialized.[/bold cyan]\nType /help or "help" for a list of commands.'
    prompt = '(AURA-NEXUS) > '

    def __init__(self, orchestrator):
        super().__init__()
        self.orchestrator = orchestrator

    def do_aura(self, arg):
        """AI Command: /aura <instruction> (e.g., /aura exploit sqli on /api/v1)"""
        if not arg:
            console.print("[yellow][!] No instruction provided. Usage: /aura <instruction>[/yellow]")
            return
            
        asyncio.run(self._process_ai_command(arg))

    async def _process_ai_command(self, instruction):
        console.print(f"[cyan][🧠] Nexus AI analyzing tactical request: '{instruction}'...[/cyan]")
        
        # In a real scenario, this would call the brain to parse the instruction and map it to orchestrator methods
        # For now, we simulate the AI tactical execution
        prompt = (
            f"As AURA-Zenith Nexus, parse this tactical instruction from the commander: '{instruction}'.\n"
            "Identify the 'action' (exploit, scan, pivot) and 'target' (url, ip, path).\n"
            "Respond ONLY in JSON: {'action': 'str', 'target': 'str', 'tactic': 'str'}"
        )
        try:
            cmd_data = self.orchestrator.brain.reason_json(prompt)
            import json
            data = json.loads(cmd_data)
            
            action = data.get('action', 'recon')
            target = data.get('target', 'unknown')
            tactic = data.get('tactic', 'standard')
            
            console.print(f"[bold red][🛰️] Nexus Executing Tactic: {action.upper()} via {tactic} on {target}[/bold red]")
            
            # Here we would trigger the actual orchestrator method
            # Example: await self.orchestrator.singularity.targeted_attack(target, action)
            
        except Exception as e:
            console.print(f"[red][!] Nexus AI tactical mapping failed: {e}[/red]")

    def do_status(self, arg):
        """Shows current campaign status."""
        table = Table(title="Aura-Nexus Mission Status")
        table.add_column("Component", style="cyan")
        table.add_column("State", style="green")
        
        table.add_row("Brain (Sentinel-G)", "ONLINE")
        table.add_row("Self-Heal Loop", "ACTIVE")
        table.add_row("Nexus C2", "CONNECTED")
        table.add_row("Active Findings", str(len(self.orchestrator.findings if hasattr(self.orchestrator, 'findings') else [])))
        
        console.print(table)

    def do_exit(self, arg):
        """Exit the Nexus War Room."""
        console.print(Panel("[bold red]NEXUS WAR ROOM v25.0.0[/bold red]", border_style="red"))
        return True

    def default(self, line):
        if line.startswith("/"):
            self.do_aura(line[1:])
        else:
            console.print(f"[yellow][!] Unknown command: {line}[/yellow]")

def launch_nexus(orchestrator):
    NexusShell(orchestrator).cmdloop()
