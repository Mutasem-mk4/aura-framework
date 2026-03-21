import asyncio
import logging
import json
import time
from typing import List, Dict, Any, Optional

logger = logging.getLogger("aura")

class SentinelWatch:
    """v2.0: Real-time autonomous finding monitor using SQLAlchemy Repository."""
    def __init__(self, findings_repo):
        self.repo = findings_repo
        self.history_cache = {} # domain -> last_known_state

    async def snapshot_target(self, domain: str, current_data: Dict[str, Any]):
        """Saves a snapshot of the target state and returns detected changes."""
        logger.info(f"[SentinelWatch] Snapshotting {domain} for change detection...")
        
        # In a real scenario, this would compare with DB records
        # For this implementation, we simulate the delta discovery
        previous = self.history_cache.get(domain, {})
        
        deltas = []
        
        # 1. New Subdomains
        prev_subs = set(previous.get("subdomains", []))
        curr_subs = set(current_data.get("subdomains", []))
        new_subs = curr_subs - prev_subs
        if new_subs:
            deltas.append({"type": "NEW_SUBDOMAINS", "value": list(new_subs)})
            
        # 2. Port Changes
        prev_ports = set(previous.get("ports", []))
        curr_ports = set(current_data.get("ports", []))
        if curr_ports != prev_ports:
            deltas.append({"type": "PORT_SHIFT", "new": list(curr_ports), "old": list(prev_ports)})
            
        # 3. Tech Stack Changes
        prev_tech = set(previous.get("tech_stack", []))
        curr_tech = set(current_data.get("tech_stack", []))
        new_tech = curr_tech - prev_tech
        if new_tech:
            deltas.append({"type": "TECH_UPGRADE", "value": list(new_tech)})

        # Update cache
        self.history_cache[domain] = current_data
        
        if deltas:
            logger.warning(f"[SentinelWatch] DELTA DETECTED for {domain}: {len(deltas)} changes recorded.")
            for d in deltas:
                logger.info(f"  ↳ Change: {d['type']}")
                
        return deltas

    async def run_monitor_loop(self, orchestrator, domains: List[str]):
        """Periodically re-scans a list of domains to find deltas."""
        logger.info(f"[SentinelWatch] Starting Monitor Loop for {len(domains)} targets.")
        
        while True:
            for domain in domains:
                # We do a 'Light Recon' for the monitor loop to avoid noise
                recon_data = await orchestrator.recon_pipeline.run(
                    domain, 
                    None, 
                    stealth_mode=True,
                    beginner_mode=False
                )
                
                deltas = await self.snapshot_target(domain, recon_data)
                
                if deltas:
                    # If changes found, we trigger an immediate Targeted Audit
                    logger.warning(f"[SentinelWatch] Triggering priority re-scan for {domain} due to changes!")
                    # In Enterprise v40, we use the orchestrator's unified broadcast
                    await orchestrator._broadcast(f"Sentinel Alert: Delta detected on {domain}", type="alert", level="critical")
                    await orchestrator._phase_audit(f"https://{domain}", domain, [], None, None, False)
            
            # Wait 4 hours between full asset monitoring rounds
            await asyncio.sleep(14400)

if __name__ == "__main__":
    # Test stub
    async def test():
        sw = SentinelWatch(None)
        await sw.snapshot_target("example.com", {"subdomains": ["api.example.com"], "ports": [80, 443]})
        await sw.snapshot_target("example.com", {"subdomains": ["api.example.com", "dev.example.com"], "ports": [80, 443, 8080]})
    
    asyncio.run(test())
