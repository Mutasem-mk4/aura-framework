import asyncio
import json
from aura.core.async_requester import AsyncRequester
from aura.ui.formatter import ZenithFormatter

async def takeover_hunt():
    formatter = ZenithFormatter()
    formatter.banner("Uber Subdomain Takeover Hunt")
    
    with open("reports/recon_omni_uber_com.json", "r") as f:
        data = json.load(f)
        subdomains = data["subdomains"]
    
    # Common fingerprints for takeovers
    fingerprints = {
        "GitHub Pages": "There isn't a GitHub Pages site here",
        "Heroku": "herokuhosted.com",
        "AWS S3": "NoSuchBucket",
        "Azure": "404 Not Found",
        "Zendesk": "Help Center Closed",
        "Shopify": "Sorry, this shop is currently unavailable",
        "Ghost": "The thing you're looking for is no longer here"
    }
    
    async with AsyncRequester(concurrency_limit=20, timeout=10) as requester:
        formatter.phase_banner("Takeover Scan", f"Auditing {len(subdomains)} subdomains for dangling records...")
        
        requests = []
        for s in subdomains:
            requests.append({"method": "GET", "url": f"https://{s}"})
        
        results = await requester.fetch_all(requests)
        
        findings = []
        for req, resp in zip(requests, results):
            if resp:
                for service, fp in fingerprints.items():
                    if fp.lower() in resp.text.lower():
                        print(f"  [bold red][🚀] POTENTIAL TAKEOVER: {req['url']} ({service})[/bold red]")
                        findings.append({
                            "url": req["url"],
                            "service": service,
                            "fingerprint": fp,
                            "status": resp.status_code
                        })
            elif not resp:
                # Potential NXDOMAIN or timeout (can be checked for DNS takeover)
                pass

    if findings:
        with open("reports/uber_takeover_findings.json", "w") as f:
            json.dump(findings, f, indent=4)
        print(f"\n[✓] Takeover hunt complete. {len(findings)} CRITICAL FINDINGS RECORDED.")
    else:
        print("\n[!] No subdomain takeovers identified on common fingerprints.")

if __name__ == "__main__":
    asyncio.run(takeover_hunt())
