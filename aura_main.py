import asyncio
import sys
import argparse
import os
from rich.console import Console
from aura.core.orchestrator import NeuralOrchestrator
from aura.core.nexus import launch_nexus

console = Console()

async def run_mission(target):
    orchestrator = NeuralOrchestrator()
    console.print(f"[bold cyan]🚀 Initializing Omni-Sovereign Mission on: {target}[/bold cyan]")
    await orchestrator.execute_advanced_chain(target)

async def run_crawl(target: str, victim: bool = False):
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
    parser = argparse.ArgumentParser(description="AURA Omni-Sovereign v25.0.0")
    parser.add_argument("target", nargs="?", help="Target domain/IP for the mission")
    parser.add_argument("--nexus", action="store_true", help="Launch interactive Nexus War Room")
    parser.add_argument("--auto-submit", action="store_true", help="Enable autonomous bounty submission (Phase 32)")
    parser.add_argument("--free-ai", action="store_true", help="Engage Zero-Cost Multi-Model AI (OpenRouter Free Tier)")
    parser.add_argument("--crawl", action="store_true", help="[v2] Run Authenticated Crawler to map all API endpoints")
    parser.add_argument("--victim", action="store_true", help="[v2] Use VICTIM session token instead of ATTACKER token")
    
    args = parser.parse_args()
    
    from aura.core import state
    if args.free_ai:
        state.OPENROUTER_FREE_MODE = True
        console.print("[bold cyan][AI] Zero-Cost Multi-Model Engine engaged.[/bold cyan]")

    if args.auto_submit:
        state.AUTO_SUBMIT = True
        console.print("[bold red][!] AURA: Autonomous Submission Protocol enabled.[/bold red]")

    if args.nexus:
        orchestrator = NeuralOrchestrator()
        launch_nexus(orchestrator)
    elif args.crawl and args.target:
        asyncio.run(run_crawl(args.target, victim=args.victim))
    elif args.target:
        asyncio.run(run_mission(args.target))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
