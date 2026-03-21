import asyncio
from aura.core.orchestrator import NeuralOrchestrator
from aura.core.storage import AuraStorage

async def main():
    target = "https://demo.owasp-juice.shop"
    print(f"[*] Starting headless Aura Assault on {target}...")
    orchestrator = NeuralOrchestrator()
    await orchestrator.execute_advanced_chain(target, swarm_mode=False)
    
    print("\n[*] Assault Complete. Extracting high-severity findings...")
    storage = AuraStorage()
    findings = storage.get_all_findings()
    
    criticals = [f for f in findings if f.get("severity") in ["CRITICAL", "HIGH"]]
    print(f"[+] Total Critical/High Findings: {len(criticals)}")
    for c in criticals:
        print(f"  - {c.get('type', 'Unknown')} | {c.get('url', 'N/A')}")
        
    print("\n[*] See data/ directory for full JSON reports.")

if __name__ == "__main__":
    asyncio.run(main())
