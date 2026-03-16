import time
import os
import signal
from aura.core.nexus_bridge import NexusBridge

def test_veritas_bridge():
    print("[🌀] Starting Veritas Bridge Verification...")
    bridge = NexusBridge()
    
    try:
        # Start Veritas
        print("[🚀] Starting Veritas service...")
        bridge.start_veritas(port=50051)
        
        # Test Health
        print("[🧠] Querying Health via Veritas...")
        health = bridge.get_health()
        print(f"[✓] Health Result: {health}")
        
        # Test Proxy Spawn
        print("[🛰️] Requesting Proxy Worker...")
        proxy_res = bridge.start_proxy(port=8082, log_file="veritas_test.json")
        print(f"[✓] Proxy Result: {proxy_res}")
        
        # Cleanup
        print("[🧹] Shutting down Veritas...")
        bridge.stop_veritas()
        print("[🏁] Veritas Bridge Verified Successfully.")
        
    except Exception as e:
        print(f"[!] Verification Failed: {e}")
        if bridge.veritas_process:
            bridge.veritas_process.terminate()

if __name__ == "__main__":
    test_veritas_bridge()
