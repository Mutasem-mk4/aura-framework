import asyncio
import json
import os
from aura.modules.recon_engine import ReconEngine
from aura.core.async_requester import AsyncRequester
from aura.ui.formatter import ZenithFormatter

async def run_fast_recon():
    formatter = ZenithFormatter()
    formatter.banner("Uber Fast-Phase Recon")
    
    recon = ReconEngine(target="uber.com")
    
    async with AsyncRequester(concurrency_limit=50, timeout=10) as requester:
        formatter.phase_banner("Discovery Phase", "Fetching subdomains and JS assets...")
        
        # We only run the most reliable discovery modules
        await asyncio.gather(
            recon._fetch_crt_sh(requester),
            recon._fetch_asn_subnets(requester),
            recon._fetch_acquisitions(requester),
            recon._fetch_js_files(requester)
        )
        
        formatter.phase_banner("JS Intelligence", f"Analyzing {len(recon.js_files)} JS files...")
        await recon._scan_all_js_files(requester)
        
    # Manually finalize to ensure we get the JSON
    recon._finalize()
    
    print(f"\n[✓] Fast Recon Complete. {len(recon.subdomains)} subdomains identified.")
    print(f"[✓] Report saved to: {recon.output_dir / f'recon_omni_{recon.base_domain}.json'}")

if __name__ == "__main__":
    asyncio.run(run_fast_recon())
