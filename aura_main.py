import asyncio
import sys
import argparse
from rich.console import Console
from aura.core.orchestrator import NeuralOrchestrator
from aura.core.nexus import launch_nexus

console = Console()

async def run_mission(target):
    orchestrator = NeuralOrchestrator()
    console.print(f"[bold cyan]🚀 Initializing Omni-Sovereign Mission on: {target}[/bold cyan]")
    await orchestrator.execute_advanced_chain(target)

def main():
    parser = argparse.ArgumentParser(description="AURA Omni-Sovereign v25.0.0")
    parser.add_argument("target", nargs="?", help="Target domain/IP for the mission")
    parser.add_argument("--nexus", action="store_true", help="Launch interactive Nexus War Room")
    parser.add_argument("--auto-submit", action="store_true", help="Enable autonomous bounty submission (Phase 32)")
    parser.add_argument("--ai-provider", choices=["gemini", "openrouter"], help="AI Provider to use (Phase 33)")
    parser.add_argument("--ai-model", help="AI Model to use (Phase 33)")
    
    args = parser.parse_args()
    
    if args.ai_provider:
        from aura.core import state
        state.AI_PROVIDER = args.ai_provider
    if args.ai_model:
        from aura.core import state
        state.OPENROUTER_MODEL = args.ai_model # Use this for either provider as default
    
    if args.auto_submit:
        from aura.core import state
        state.AUTO_SUBMIT = True
        console.print("[bold red][!] AURA: Autonomous Submission Protocol enabled.[/bold red]")

    if args.nexus:
        orchestrator = NeuralOrchestrator()
        launch_nexus(orchestrator)
    elif args.target:
        asyncio.run(run_mission(args.target))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
