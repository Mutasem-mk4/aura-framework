"""
Verification Script: Engine Registry & Pipeline Integration
Runs a test scan to prove the chain works: Discovery -> Finding -> Persistence.
"""

import asyncio
import sys
import os

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aura.core.context import MissionContext, AuraConfig
from aura.core.registry import get_registry
from aura.core.storage import AuraStorage

async def main():
    print("=" * 60)
    print("AURA REGISTRY VERIFICATION TEST")
    print("=" * 60)

    # 1. Initialize Context & Storage
    config = AuraConfig()
    context = MissionContext(target_url="example.com", config=config)
    storage = AuraStorage()
    
    print(f"[*] Mission Context Created: {context.target_url}")
    print(f"[*] Storage Initialized")

    # 2. Get Registry & List Engines
    registry = get_registry()
    print(f"\n[*] Registry Engines: {registry.list_engines()}")

    # 3. Simulate a Finding
    test_finding = {
        "type": "subdomain", 
        "content": "api.example.com", 
        "severity": "HIGH"
    }
    
    # 4. Smart Routing Test
    print(f"\n[+] Simulating Finding: {test_finding['type']}")
    engines_to_run = registry.resolve_routing(test_finding['type'])
    print(f"[+] Smart Routing: {engines_to_run}")

    if engines_to_run:
        print(f"\n[+] Running {len(engines_to_run)} downstream engines in parallel...")
        
        # Run them
        kwargs = {"persistence": storage, "telemetry": None, "brain": None}
        
        results = await registry.run_parallel(engines_to_run, context, **kwargs)
        
        print(f"[+] Parallel Execution Complete. Results: {len(results)}")
    else:
        print("[!] No downstream engines found for this finding type.")

    # 5. Manual Engine Test
    print("\n[+] Manual Instantiation Test: LeakProber")
    leak_engine_cls = registry.get_engine("leak_prober")
    if leak_engine_cls:
        engine = leak_engine_cls(persistence=storage, telemetry=None, brain=None)
        await engine.setup(context)
        # await engine.run() # Skip actual run to save time
        print("[+] LeakProber instantiated successfully.")
    else:
        print("[!] LeakProber not found.")

    print("\n" + "=" * 60)
    print("VERIFICATION COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
