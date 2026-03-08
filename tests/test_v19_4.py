import asyncio
from aura.core.state import GEMINI_API_KEY
from aura.core.brain import AuraBrain
from aura.modules.poc_engine import PoCEngine

async def test_sovereignty():
    print(f"[*] Testing AI Key Loading: {'LOADED' if GEMINI_API_KEY else 'MISSING'}")
    
    brain = AuraBrain()
    print(f"[*] Testing AI Brain: {'ENABLED' if brain.enabled else 'DISABLED'}")
    
    poc = PoCEngine()
    print("[*] Testing PoCEngine expansion...")
    if hasattr(poc, 'verify_time_sqli') and hasattr(poc, 'verify_xss'):
        print("[+] SUCCESS: PoCEngine has verify_time_sqli and verify_xss methods.")
    else:
        print("[-] FAILURE: PoCEngine missing expected methods.")

if __name__ == "__main__":
    asyncio.run(test_sovereignty())
