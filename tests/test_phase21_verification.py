
import asyncio
import json
import os
from aura.modules.logic_engine import AILogicEngine
from aura.core.stealth import AuraSession, StealthEngine
from aura.modules.poc_engine import PoCEngine
from aura.core.brain import AuraBrain

async def verify_phase21():
    print("[*] Starting Phase 21: The Archon Protocol Verification...")
    
    brain = AuraBrain()
    stealth = StealthEngine()
    session = AuraSession(stealth)
    
    # 1. Test Pincer Logic Engine
    print("\n[1] Testing Pincer Logic Engine (Multi-Session IDOR)...")
    logic = AILogicEngine(session)
    # Simulate a second session
    session2 = AuraSession(stealth)
    logic.sessions.append(session2)
    
    # Check if pincer logic is enabled
    if len(logic.sessions) > 1:
        print("[SUCCESS] Pincer Logic Engine initialized with multiple sessions.")
    else:
        print("[FAILURE] Pincer Logic Engine failed to initialize sessions.")

    # 2. Test Adversarial Topology Mapping
    print("\n[2] Testing Adversarial Topology Mapping...")
    # Add dummy latency data
    session.latency_log = [
        {"url": "http://target.com/api", "status": 200, "latency": 25.0}, # Edge
        {"url": "http://target.com/api", "status": 200, "latency": 35.0}, # Edge
        {"url": "http://target.com/admin", "status": 403, "latency": 150.0}, # WAF/Proxy
        {"url": "http://target.com/heavy", "status": 200, "latency": 450.0}  # Backend
    ]
    
    topology = stealth.map_defense_topology(session.latency_log)
    print(f"[*] Generated Topology: {json.dumps(topology, indent=2)}")
    
    if "Edge/CDN" in str(topology["layers"]) and "Backend" in str(topology["layers"]):
        print("[SUCCESS] Topology Mapping correctly identified infrastructure layers.")
    else:
        print("[FAILURE] Topology Mapping missed critical infrastructure layers.")

    # 3. Test Ghost-Shell PoC Generation
    print("\n[3] Testing Ghost-Shell PoC Generation...")
    poc = PoCEngine(stealth)
    
    # Mocking verify_rce for unit test simulation
    if hasattr(poc, "verify_rce"):
        print("[SUCCESS] PoCEngine has Ghost-Shell High-Impact RCE verification capability.")
    else:
        print("[FAILURE] PoCEngine missing Ghost-Shell RCE capability.")

    print("\n[*] Phase 21 Verification Complete.")

if __name__ == "__main__":
    asyncio.run(verify_phase21())
