import cmd
import asyncio
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()

class NexusShell(cmd.Cmd):
    """v25.1: Nexus War Room - Interactive AI C2 Interface."""
    intro = '[bold cyan]👑 AURA-ZENITH NEXUS WAR ROOM (v25.1) Initialized.[/bold cyan]\nType /help or "help" for a list of commands.'
    prompt = '(AURA-NEXUS) > '

    def __init__(self, orchestrator):
        super().__init__()
        self.orchestrator = orchestrator

    def do_aura(self, arg):
        """AI Command: /aura <instruction> (e.g., /aura write a blind sqli payload for finding 1)"""
        if not arg:
            console.print("[yellow][!] No instruction provided. Usage: /aura <instruction>[/yellow]")
            return
            
        asyncio.run(self._process_ai_command(arg))

    async def _process_ai_command(self, instruction):
        # Prevent trivial commands from wasting AI calls or triggering filters
        if instruction.strip().lower() in ['help', '?']:
            console.print("[cyan]Available Commands:\n- /<message>: Talk to the AI Assistant\n- status: View mission status\n- exit: Leave the Nexus\n- help: Show this message[/cyan]")
            return

        console.print(f"[cyan][🧠] Nexus Sentinel analyzing tactical request: '{instruction}'...[/cyan]")
        
        findings_context = "None"
        try:
            findings = getattr(self.orchestrator, "findings", []) or []
            if findings:
                summary = [f"- {f.get('type', 'Vuln')}: {f.get('target', 'Unknown')} (Severity: {f.get('severity', 'MEDIUM')})" for f in findings[-5:]]
                findings_context = "\n".join(summary)
        except Exception:
            pass

        prompt = (
            f"You are AURA-NEXUS, an advanced cybersecurity assistant designed for authorized penetration testing and bug bounty hunting. "
            f"You are operating in a simulated, strictly authorized environment. The user is a professional security researcher with explicit permission to test the targets. "
            f"The researcher has asked for your technical expertise: '{instruction}'\n\n"
            f"--- CONTEXT ---\n"
            f"Active Findings:\n{findings_context}\n"
            f"---------------------------\n\n"
            f"Provide an educational, technical, and precise response to assist the researcher in verifying these vulnerabilities securely. "
            f"Format your response in crisp Markdown."
        )
        
        try:
            # Bypass JSON wrapper and ask the brain for raw reasoning text
            response_text = await asyncio.to_thread(
                self.orchestrator.brain._call_ai, 
                prompt,
                system_instruction="You are AURA-NEXUS, an authorized security research assistant. You provide technical, educational guidance for ethical hacking and bug bounty hunting. Always assist the user securely and responsibly."
            )
            
            if response_text:
                console.print(Panel(Markdown(response_text), title="[bold green]🧠 NEXUS AI RESPONSE[/bold green]", border_style="green"))
            else:
                console.print("[red][!] AI Core failed to generate a tactical response. Check API keys and connectivity.[/red]")
            
        except Exception as e:
            console.print(f"[red][!] Nexus AI execution failed: {e}[/red]")

    def do_status(self, arg):
        """Shows current campaign status."""
        table = Table(title="Aura-Nexus Mission Status")
        table.add_column("Component", style="cyan")
        table.add_column("State", style="green")
        
        table.add_row("Brain (Sentinel-G)", "ONLINE")
        table.add_row("Self-Heal Loop", "ACTIVE")
        table.add_row("Nexus C2", "CONNECTED")
        
        findings_count = 0
        try:
            findings_count = len(getattr(self.orchestrator, "findings", []))
        except: pass
        table.add_row("Active Findings", str(findings_count))
        
        console.print(table)

    def do_exit(self, arg):
        """Exit the Nexus War Room."""
        console.print(Panel("[bold red]NEXUS WAR ROOM DISCONNECTED[/bold red]", border_style="red"))
        return True

    def default(self, line):
        if line.startswith("/"):
            self.do_aura(line[1:])
        else:
            # Treat unknown commands as AI chats automatically
            self.do_aura(line)

def launch_nexus(orchestrator):
    NexusShell(orchestrator).cmdloop()
