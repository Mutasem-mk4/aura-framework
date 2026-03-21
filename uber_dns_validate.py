import asyncio
import json
import socket
from aura.ui.formatter import ZenithFormatter

async def validate_dns():
    formatter = ZenithFormatter()
    formatter.banner("Uber Surface Validation")
    
    with open("reports/recon_omni_uber_com.json", "r") as f:
        data = json.load(f)
        subdomains = data["subdomains"]
    
    formatter.phase_banner("DNS Resolution", f"Checking {len(subdomains)} subdomains...")
    
    reachable = []
    
    def resolve_sync(domain):
        try:
            addr = socket.gethostbyname(domain)
            return addr
        except:
            return None

    # We use a ThreadPool for DNS resolution because socket.gethostbyname is blocking
    loop = asyncio.get_event_loop()
    tasks = []
    for domain in subdomains:
        tasks.append(loop.run_in_executor(None, resolve_sync, domain))
    
    results = await asyncio.gather(*tasks)
    
    for domain, addr in zip(subdomains, results):
        if addr:
            reachable.append({"domain": domain, "ip": addr})
            print(f"  [bold green][✓] {domain} -> {addr}[/bold green]")

    with open("reports/reachable_uber_subdomains.json", "w") as f:
        json.dump(reachable, f, indent=4)
    
    print(f"\n[✓] Validation complete. {len(reachable)} reachable subdomains found.")

if __name__ == "__main__":
    asyncio.run(validate_dns())
