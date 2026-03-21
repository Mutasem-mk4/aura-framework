import asyncio
import json
from aura.core.async_requester import AsyncRequester
from aura.ui.formatter import ZenithFormatter

async def internal_extraction():
    formatter = ZenithFormatter()
    formatter.banner("Uber Internal Surface Extraction")
    
    internal_targets = [
        "aaacp.uberinternal.com",
        "blogadmin.uberinternal.com",
        "newsroomadmin.uberinternal.com",
        "chef.uberinternal.com",
        "team.uberinternal.com",
        "yolo.uberinternal.com",
        "outages.uberinternal.com"
    ]
    
    paths = [
        "/",
        "/admin",
        "/api/v1",
        "/swagger-ui.html",
        "/metrics",
        "/env",
        "/actuator",
        "/.git/config",
        "/login"
    ]
    
    async with AsyncRequester(concurrency_limit=20, timeout=10) as requester:
        formatter.phase_banner("Internal Probing", f"Testing {len(internal_targets) * len(paths)} internal-facing endpoints...")
        
        requests = []
        for t in internal_targets:
            for p in paths:
                requests.append({"method": "GET", "url": f"https://{t}{p}", "meta": {"target": t, "path": p}})
        
        results = await requester.fetch_all(requests)
        
        findings = []
        for req, resp in zip(requests, results):
            if resp and resp.status_code in [200, 301, 302, 401, 403]:
                info = {
                    "url": req["url"],
                    "status": resp.status_code,
                    "length": len(resp.text)
                }
                findings.append(info)
                color = "green" if resp.status_code == 200 else "yellow"
                print(f"  [{color}][{info['status']}] {info['url']} (Size: {info['length']})[/{color}]")

    if findings:
        with open("reports/internal_extraction_results.json", "w") as f:
            json.dump(findings, f, indent=4)
        print(f"\n[✓] Internal extraction complete. Findings saved.")

if __name__ == "__main__":
    asyncio.run(internal_extraction())
