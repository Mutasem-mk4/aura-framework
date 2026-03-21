"""
Aura - Broken Crystals Attack Test
Target: https://brokencrystals.com
"""
import asyncio
import json
import httpx
from aura.modules.frontend_deconstructor import FrontendDeconstructor

TARGET = "https://brokencrystals.com"

class MockContext:
    def __init__(self, target):
        self.target = target
        self.target_url = target
        self.intel = {}
    def get_intel(self):
        return self.intel

async def main():
    print(f"\n{'='*60}")
    print(f"  🎯 AURA ASSAULT: Broken Crystals (Modern SPA Targets)")
    print(f"  Target: {TARGET}")
    print(f"{'='*60}\n")
    
    ctx = MockContext(TARGET)
    
    print("[+] Firing Frontend Deconstructor ...")
    fd = FrontendDeconstructor()
    fd.context = ctx
    fd.target = TARGET
    fd.emit_progress = lambda **kw: None
    fd.emit_vulnerability = lambda v: fd.results.append(v) if hasattr(fd, 'results') else None
    
    fd_findings = []
    try:
        fd_findings = await fd.run()
    except Exception as e:
        print(f"    [!] FD Error: {e}")
        
    print(f"\n[✅] Discovered {len(fd_findings)} logic endpoints/secrets hidden in Broken Crystals React/Angular code!")
    for f in fd_findings[:10]:
        print(f"  -> {f.get('content')}")

if __name__ == "__main__":
    asyncio.run(main())
