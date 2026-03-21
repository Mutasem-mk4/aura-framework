import asyncio
import json
import os
from aura.modules.recon_engine import ReconEngine
from aura.core.async_requester import AsyncRequester
from aura.ui.formatter import ZenithFormatter

async def run_terminal_recon():
    formatter = ZenithFormatter()
    formatter.banner("Uber Terminal Velocity Recon")
    
    recon = ReconEngine(target="uber.com")
    
    async with AsyncRequester(concurrency_limit=100, timeout=15) as requester:
        formatter.phase_banner("Discovery Phase", "Fetching subdomains ONLY...")
        
        # Phase 1: Subdomain Discovery ONLY
        await asyncio.gather(
            recon._fetch_crt_sh(requester),
            recon._fetch_asn_subnets(requester),
            recon._fetch_acquisitions(requester),
            recon._fetch_mobile_endpoints(requester)
        )
        
    # Manually finalize to ensure we get the JSON
    recon._finalize()
    
    print(f"\n[✓] Terminal Recon Complete. {len(recon.subdomains)} subdomains identified.")
    print(f"[✓] Report saved to: {recon.output_dir / f'recon_omni_{recon.base_domain}.json'}")

if __name__ == "__main__":
    asyncio.run(run_terminal_recon())
