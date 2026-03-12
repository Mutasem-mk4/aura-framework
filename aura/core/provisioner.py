import os
import sys
import shutil
import subprocess
from rich.console import Console

console = Console()

class AuraProvisioner:
    """v25.0 OMEGA: Autonomous Dependency Provisioner."""
    
    _has_run = False

    @classmethod
    def check_and_provision(cls):
        """Validates the local environment and attempts auto-remediation."""
        if cls._has_run:
            return
        cls._has_run = True
        
        console.print("[bold cyan][⚙️] OMEGA Provisioner: Verifying environment integrity...[/bold cyan]")
        
        # Node.js Check
        if not shutil.which("node"):
            console.print("[dim yellow][!] Warning: Node.js not found. Advanced JS analysis features might be degraded.[/dim yellow]")
            
        # Nuclei Check
        if not shutil.which("nuclei"):
            console.print("[dim yellow][!] Warning: Nuclei binary missing. Attempting autonomous installation...[/dim yellow]")
            if shutil.which("go"):
                try:
                    subprocess.run(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"], 
                                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    console.print("[bold green][✓] Nuclei installed successfully via Go.[/bold green]")
                except subprocess.CalledProcessError:
                    console.print("[dim red][!] Failed to install Nuclei automatically. Run: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/dim red]")
            else:
                console.print("[dim red][!] Go compiler is not installed. Cannot auto-install Nuclei.[/dim red]")
                
        # Python Package Check
        try:
            import esprima
        except ImportError:
            console.print("[dim yellow][!] Warning: Python package 'esprima' missing. Attempting autonomous installation...[/dim yellow]")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "esprima"], 
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                console.print("[bold green][✓] Package 'esprima' installed successfully.[/bold green]")
            except subprocess.CalledProcessError:
                console.print("[dim red][!] Failed to install 'esprima'. Please run: pip install esprima[/dim red]")
