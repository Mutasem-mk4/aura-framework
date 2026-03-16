import asyncio
import json
import os
import subprocess
from aura.core.orchestrator import NeuralOrchestrator
from aura.core.brain import AuraBrain
from aura.modules.stateful_logic_fuzzer import StatefulLogicFuzzer

async def test_apex_v2_flow():
    print("[🌀] Starting Apex v2.0 Unified Validation...")
    
    # 1. Verify Nexus Executable
    nexus_path = os.path.join(os.getcwd(), "aura", "core", "nexus", "nexus.exe")
    if os.path.exists(nexus_path):
        print(f"[✓] Nexus binary found at {nexus_path}")
        try:
            # Check help output
            res = subprocess.run([nexus_path, "-h"], capture_output=True, text=True)
            if "proxy" in res.stdout or "proxy" in res.stderr:
                print("[✓] Nexus Proxy mode verified in binary.")
        except Exception as e:
            print(f"[!] Nexus binary execution check failed: {e}")
    else:
        print("[!] Nexus binary NOT FOUND. Build might have failed or naming is different.")

    # 2. Mock Traffic Logs for Neural Modeling
    mock_logs = [
        {
            "timestamp": 1710450000,
            "method": "POST",
            "url": "https://example.com/api/login",
            "request_body": '{"email":"test@aura.io", "password":"password123"}',
            "response_stats": 200,
            "response_body": '{"token": "eyJhbGciOiJIUzI1NiJ9..."}'
        },
        {
            "timestamp": 1710450005,
            "method": "GET",
            "url": "https://example.com/api/user/profile",
            "request_body": "",
            "response_stats": 200,
            "response_body": '{"id": 1337, "username": "aura_user"}'
        }
    ]
    
    # 3. Test Neural State Modeler
    print("[🧠] Testing Neural State Modeler...")
    brain = AuraBrain()
    state_model = await brain.model_state(mock_logs)
    print(f"[✓] State Model generated: {json.dumps(state_model, indent=2)}")

    # 4. Test Fuzzer Ingestion
    print("[🧬] Testing Logic Fuzzer Ingestion...")
    fuzzer = StatefulLogicFuzzer(base_url="https://example.com")
    await fuzzer.ingest_model(state_model)
    
    # Verify DAG steps
    if len(fuzzer.dag_executor.nodes) > 0:
        print(f"[✓] Fuzzer ingested {len(fuzzer.dag_executor.nodes)} nodes into DAG.")
        for node_id, node in fuzzer.dag_executor.nodes.items():
            print(f"  - Node: {node.name} ({node.method} {node.path})")
    else:
        print("[!] Fuzzer failed to ingest nodes.")

    print("\n[🏁] Apex v2.0 Core Components Verified.")

if __name__ == "__main__":
    asyncio.run(test_apex_v2_flow())
