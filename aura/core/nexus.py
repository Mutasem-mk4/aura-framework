import cmd
import asyncio
import os
import tarfile
import zipfile
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

from aura.ui.formatter import console

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

    def do_analyze(self, arg):
        """AI Command: /analyze <url> <optional_filepath>
        Analyzes a target website and optionally reads its source code archive (.zip, .tar.gz) for Whitebox testing."""
        args = arg.split()
        if not args:
            console.print("[yellow][!] Usage: /analyze <url> [filepath][/yellow]")
            return
            
        url = args[0]
        filepath = args[1] if len(args) > 1 else None
        
        source_context = ""
        if filepath and os.path.exists(filepath):
            console.print(f"[cyan][*] Extracting source code from {filepath}...[/cyan]")
            extracted_text = ""
            allowed_exts = {".py", ".js", ".php", ".html", ".ts", ".go", ".java", ".c", ".cpp", ".txt"}
            
            try:
                if filepath.endswith('.tar.gz') or filepath.endswith('.tar'):
                    with tarfile.open(filepath, 'r:*') as tar:
                        for member in tar.getmembers():
                            if member.isfile() and any(member.name.endswith(ext) for ext in allowed_exts):
                                f = tar.extractfile(member)
                                if f:
                                    content = f.read().decode('utf-8', errors='ignore')
                                    extracted_text += f"\\n--- {member.name} ---\\n{content[:5000]}"
                elif filepath.endswith('.zip'):
                    with zipfile.ZipFile(filepath, 'r') as z:
                        for name in z.namelist():
                            if any(name.endswith(ext) for ext in allowed_exts):
                                with z.open(name) as f:
                                    content = f.read().decode('utf-8', errors='ignore')
                                    extracted_text += f"\\n--- {name} ---\\n{content[:5000]}"
                else:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        extracted_text = f.read()
                        
                if extracted_text:
                    if len(extracted_text) > 80000:
                        extracted_text = extracted_text[:80000] + "\\n...[TRUNCATED]..."
                    source_context = f"\\n\\nSource Code Context:\\n{extracted_text}"
            except Exception as e:
                console.print(f"[red][!] Error reading file: {e}[/red]")
                
        instruction = f"Please perform a thorough Whitebox analysis on the target URL: {url}."
        if source_context:
            instruction += f" I am providing you with the source code of the application. Locate any vulnerabilities (like IDOR, XXE, SQLi, Logic flaws) and provide the exact payload or exploit steps targeting {url}.{source_context}"
            
        asyncio.run(self._process_ai_command(instruction))


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
