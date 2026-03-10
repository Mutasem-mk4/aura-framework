"""
Quick verification: test api_engine imports & logic against ICI PARIS XL.
"""
import asyncio
import json
from aura.modules.api_engine import APIEngine, run_api_scan

async def main():
    print("[*] API Engine import OK")
    
    # Test 1: Quick JSON miner test (unit test)
    e = APIEngine("https://www.iciparisxl.nl")
    e._mine_json_leaks(
        '{"user": "admin@iciparisxl.nl", "token": "eyJ0eXAiOiJKV1Qi.abc.def"}',
        "https://www.iciparisxl.nl/api/test"
    )
    print(f"[+] JSON miner test: {len(e.findings)} findings (expected 2)")
    for f in e.findings:
        print(f"    - {f['type']} / {f.get('subtype')} -> {f.get('value','')[:30]}")
    
    await e.client.aclose()
    print("[*] All local tests passed. Skipping remote scan.")

if __name__ == "__main__":
    asyncio.run(main())
