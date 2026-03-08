
import asyncio
import json
import os
from aura.core.storage import AuraStorage
from aura.core.zenith_reporter import ZenithReporter
from aura.core.orchestrator import NeuralOrchestrator
from aura.core.brain import AuraBrain

async def verify_phase20():
    print("[*] Starting Phase 20: Zenith Sovereignty Verification...")
    
    db = AuraStorage()
    brain = AuraBrain()
    reporter = ZenithReporter(brain)
    
    # 1. Test Zenith Report Finalizer
    print("\n[1] Testing Zenith Report Generation...")
    target = "api.zenith-test.com"
    finding = {
        "type": "Blind SQL Injection",
        "severity": "CRITICAL",
        "content": "Vulnerable parameter 'id' on endpoint /api/v1/user. Payload: ' OR 1=1--",
        "url": "https://api.zenith-test.com/api/v1/user?id=1"
    }
    
    report_path = await reporter.generate_final_report(target, finding)
    print(f"Report Location: {report_path}")
    
    if os.path.exists(report_path):
        print("[SUCCESS] Zenith report successfully generated.")
        with open(report_path, "r") as f:
             print("Report Preview (First 5 lines):")
             print("\n".join(f.readlines()[:5]))
    else:
        print("[FAILURE] Zenith report generation failed.")

    # 2. Test Sovereign Intelligence Bridge
    print("\n[2] Testing Sovereign Intelligence Bridge...")
    tech_stack = "nginx/1.18.0"
    payload = "'; DROP TABLE users; --"
    
    print(f"Saving intelligence for '{tech_stack}'...")
    db.save_sovereign_intel("nginx", "SQLi", payload)
    
    print("Retrieving cross-domain intelligence...")
    intel = db.get_sovereign_intel("nginx/1.20.0") # Different version to test LIKE match
    print(f"Intelligence found: {intel}")
    
    if any(i['successful_payload'] == payload for i in intel):
        print("[SUCCESS] Sovereign Bridge correctly shared intelligence cross-version.")
    else:
        print("[FAILURE] Sovereign Bridge failed to retrieve intel.")

    # 3. Test Self-Healing Mission State
    print("\n[3] Testing Self-Healing Mission State Persistence...")
    mission_target = "resilient-target.com"
    stats = {"findings": 5, "urls": 150}
    full_state = {"step": "DAST_COMPLETE", "discovered_urls": ["url1", "url2"]}
    
    print(f"Persisting mission state for '{mission_target}'...")
    db.save_mission_state(mission_target, "DAST_COMPLETE", stats, full_state)
    
    print("Retrieving mission state...")
    restored_state = db.get_mission_state(mission_target)
    print(f"Restored Step: {restored_state['current_step']}")
    
    if restored_state and restored_state['current_step'] == "DAST_COMPLETE":
        print("[SUCCESS] Mission state successfully persisted and restored.")
    else:
        print("[FAILURE] Mission state restoration failed.")

    print("\n[*] Phase 20 Verification Complete.")

if __name__ == "__main__":
    asyncio.run(verify_phase20())
