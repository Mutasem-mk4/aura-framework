import asyncio
import json
from aura.modules.recon_engine import ReconEngine
from aura.core.async_requester import AsyncRequester

async def main():
    engine = ReconEngine("uber.com")
    
    async with AsyncRequester() as requester:
        await engine._fetch_asn_subnets(requester)
        await engine._fetch_acquisitions(requester)
        
    out = {
        "asn_ranges": engine.asn_ranges,
        "horizontal_domains": list(engine.horizontal_domains)
    }
    with open("recon_uber_phase58.json", "w") as f:
        json.dump(out, f, indent=4)
        
    print("[*] Saved results to recon_uber_phase58.json")

if __name__ == "__main__":
    asyncio.run(main())
