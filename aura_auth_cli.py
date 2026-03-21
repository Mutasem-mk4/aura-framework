import sys
import json
from aura_auth import vault
from aura.ui.formatter import console

def show_help():
    console.print("[bold cyan]Aura Auth CLI[/bold cyan]")
    console.print("  Usage: [yellow]python aura_auth_cli.py <command> [args][/yellow]")
    console.print("  Commands:")
    console.print("    [green]add <domain> <headers_json>[/green]  - Add a session (e.g., '{\"Authorization\": \"Bearer ...\"}')")
    console.print("    [green]list[/green]                         - List all stored sessions")
    console.print("    [green]clear <domain>[/green]               - Remove session for a domain")

def add_session(domain: str, headers_json: str):
    try:
        headers = json.loads(headers_json)
        vault.set_session(domain, headers)
    except Exception as e:
        console.print(f"  [red][!] Error parsing JSON: {e}[/red]")

def list_sessions():
    console.print("[bold blue]Current Active Sessions:[/bold blue]")
    if not vault.data:
        console.print("  [yellow]No sessions stored.[/yellow]")
        return
    for domain, headers in vault.data.items():
        console.print(f"  -> [cyan]{domain}[/cyan] (Headers: {list(headers.keys())})")

def clear_session(domain: str):
    if domain in vault.data:
        del vault.data[domain]
        vault.save()
        console.print(f"  [bold green][+][/bold green] Session for {domain} cleared.")
    else:
        console.print(f"  [yellow][!] No session found for {domain}[/yellow]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        show_help()
        sys.exit(1)
        
    cmd = sys.argv[1]
    if cmd == "add" and len(sys.argv) == 4:
        add_session(sys.argv[2], sys.argv[3])
    elif cmd == "list":
        list_sessions()
    elif cmd == "clear" and len(sys.argv) == 3:
        clear_session(sys.argv[2])
    else:
        show_help()
