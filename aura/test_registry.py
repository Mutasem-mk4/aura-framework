import sys
import os
import asyncio
import traceback

# Ensure project root is in path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, project_root)

from aura.core.registry import ModuleRegistry
from aura.core.orchestrator import NeuralOrchestrator

async def test_registry():
    try:
        print("Testing ModuleRegistry discovery...")
        registry = ModuleRegistry()
        registry.discover()
        
        engines = registry.list_engines()
        print(f"Discovered engines: {engines}")
        
        print("\nTesting Orchestrator initialization...")
        orchestrator = NeuralOrchestrator()
        
        print(f"Orchestrator scanner: {orchestrator.scanner}")
        if orchestrator.scanner:
            print(f"Scanner telemetry: {getattr(orchestrator.scanner, 'telemetry', None)}")
        
        print(f"Orchestrator telemetry: {orchestrator.telemetry}")
    except Exception:
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(test_registry())
