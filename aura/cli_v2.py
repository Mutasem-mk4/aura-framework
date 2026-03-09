"""
Aura v2 — Main CLI Entry Point
This file lives inside the `aura` package so pip can find it via pyproject.toml entry_points.
Route: `aura` command -> aura.cli_v2:main -> dispatches to correct engine.
"""

import asyncio
import sys
import argparse
import os
from rich.console import Console

console = Console()


async def _run_mission(target: str):
    from aura.core.orchestrator import NeuralOrchestrator
    orchestrator = NeuralOrchestrator()
    console.print(f"[bold cyan]🚀 Initializing Omni-Sovereign Mission on: {target}[/bold cyan]")
    await orchestrator.execute_advanced_chain(target)


async def _run_crawl(target: str, victim: bool = False):
    """Runs authenticated crawler with attacker or victim cookies."""
    from dotenv import load_dotenv
    load_dotenv()
    from aura.modules.auth_crawler import run_crawler

    cookie_key = "AUTH_TOKEN_VICTIM" if victim else "AUTH_TOKEN_ATTACKER"
    cookies = os.getenv(cookie_key, "")

    if not cookies:
        console.print(f"[bold red]❌ {cookie_key} not found in .env![/bold red]")
        console.print("[yellow]Hint: Add your session cookies to the .env file.[/yellow]")
        return

    account_type = "VICTIM" if victim else "ATTACKER"
    console.print(f"[bold cyan]🕷️  Starting Authenticated Crawl: {target} [{account_type} session][/bold cyan]")
    await run_crawler(target, cookies)


def main():
    parser = argparse.ArgumentParser(
        prog="aura",
        description="AURA v2 — Professional Bug Bounty & Pentest Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aura example.com                       # Full automated scan
  aura example.com --crawl               # Authenticated API crawler (attacker session)
  aura example.com --crawl --victim      # Authenticated API crawler (victim session)
  aura example.com --free-ai             # Scan with local Ollama AI (zero cost)
  aura --nexus                           # Launch interactive war room
        """
    )

    parser.add_argument("target", nargs="?", help="Target domain (e.g. example.com)")
    parser.add_argument("--nexus", action="store_true", help="Launch interactive Nexus War Room")
    parser.add_argument("--auto-submit", action="store_true", help="Enable autonomous bounty submission")
    parser.add_argument("--free-ai", action="store_true", help="Use local Ollama AI (zero cost)")
    parser.add_argument("--crawl", action="store_true", help="[v2] Authenticated crawler — maps all API endpoints")
    parser.add_argument("--victim", action="store_true", help="[v2] Use VICTIM session token for crawl/attack")

    args = parser.parse_args()

    from aura.core import state
    if args.free_ai:
        state.OPENROUTER_FREE_MODE = True
        console.print("[bold cyan][AI] Zero-Cost Ollama Engine engaged.[/bold cyan]")

    if args.auto_submit:
        state.AUTO_SUBMIT = True
        console.print("[bold red][!] Autonomous Submission Protocol enabled.[/bold red]")

    if args.nexus:
        from aura.core.orchestrator import NeuralOrchestrator
        from aura.core.nexus import launch_nexus
        orchestrator = NeuralOrchestrator()
        launch_nexus(orchestrator)
    elif args.crawl and args.target:
        asyncio.run(_run_crawl(args.target, victim=args.victim))
    elif args.target:
        asyncio.run(_run_mission(args.target))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
