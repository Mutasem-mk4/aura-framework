import json
import httpx
import os

CHAOS_INDEX_URL = "https://chaos-data.projectdiscovery.io/index.json"

async def get_uber_subdomains():
    print("[*] Contacting Chaos Data for Uber infrastructure map...")
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get(CHAOS_INDEX_URL)
            r.raise_for_status()
            data = r.json()
            
            uber_programs = [p for p in data if "uber" in p.get("name", "").lower()]
            
            print(f"\n[💀] Found {len(uber_programs)} Uber-related programs in Chaos index.")
            
            sorted_programs = sorted(uber_programs, key=lambda x: x.get("count", 0), reverse=True)
            
            for p in sorted_programs[:5]:
                print(f"  • {p['name']}: {p['count']} subdomains (Platform: {p.get('platform', 'N/A')})")
                
            # Focus on the main Uber wildcard
            main_uber = next((p for p in uber_programs if p['name'].lower() == "uber"), None)
            if main_uber:
                print(f"\n[🔥] Target Confirmed: Uber Main Wildcard")
                print(f"    Subdomains: {main_uber['count']}")
                # We can't download all subdomains here without knowing the exact Chaos URL for the zip,
                # but we can simulate the 'Surgical Strike' on known critical Uber subdomains if needed.
                # Usually, 'staging-api.uber.com', 'dev-api.uber.com', etc. are good targets.
                
        except Exception as e:
            print(f"[!] Error fetching index: {e}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(get_uber_subdomains())
