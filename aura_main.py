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
    parser = argparse.ArgumentParser(description="AURA Omni-Sovereign v16.1")
    parser.add_argument("target", nargs="?", help="Target domain/IP for the mission")
    parser.add_argument("--nexus", action="store_true", help="Launch interactive Nexus War Room")
    
    args = parser.parse_args()
    
    if args.nexus:
        orchestrator = NeuralOrchestrator()
        launch_nexus(orchestrator)
    elif args.target:
        asyncio.run(run_mission(args.target))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
