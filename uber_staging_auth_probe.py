import asyncio
import json
from aura.core.async_requester import AsyncRequester
from aura.ui.formatter import ZenithFormatter

async def probe_staging_auth():
    formatter = ZenithFormatter()
    formatter.banner("Uber Staging Auth Strike")
    
    target = "auth3-staging.uber.com"
    
    # Critical paths to probe
    paths = [
        "/appleloginsuccess",
        "/facebookloginsuccess",
        "/googleloginsuccess",
        "/.well-known/openid-configuration",
        "/env",
        "/health",
        "/actuator",
        "/metrics",
        "/debug",
        "/swagger-ui.html",
        "/api-docs",
        "/v2/api-docs",
        "/config",
        "/status"
    ]
    
    async with AsyncRequester(concurrency_limit=10, timeout=12) as requester:
        formatter.phase_banner("Staging Probe", f"Analyzing {len(paths)} paths on {target}...")
        
        requests = []
        for p in paths:
            requests.append({"method": "GET", "url": f"https://{target}{p}"})
        
        results = await requester.fetch_all(requests)
        
        findings = []
        for req, resp in zip(requests, results):
            if resp:
                status = resp.status_code
                length = len(resp.text)
                
                # Check for 200 OK or interesting error codes
                if status == 200:
                    print(f"  [bold green][🔥] 200 OK: {req['url']} (Size: {length})[/bold green]")
                    findings.append({
                        "url": req["url"],
                        "status": status,
                        "length": length,
                        "type": "Direct Access",
                        "snippet": resp.text[:500]
                    })
                    # Heuristic: Check for JSON config or secrets in snippet
                    if "password" in resp.text.lower() or "secret" in resp.text.lower():
                        print(f"  [bold red][!] POTENTIAL SECRET DISCLOSED IN {req['url']}[/bold red]")
                
                elif status in [401, 403]:
                    # Check if body is non-empty (sometimes 403 leaks info)
                    if length > 500:
                        print(f"  [yellow][{status}] Interesting Response Body: {req['url']} ({length})[/yellow]")
                        findings.append({
                            "url": req["url"],
                            "status": status,
                            "length": length,
                            "type": "Information Disclosure (Error Body)"
                        })
                
                elif status == 500:
                    print(f"  [cyan][500] Error Leak? {req['url']}[/cyan]")

    if findings:
        with open("reports/uber_staging_bypass_findings.json", "w") as f:
            json.dump(findings, f, indent=4)
        print(f"\n[✓] Staging probe complete. {len(findings)} findings recorded.")
    else:
        print("\n[!] No direct staging leaks found. Escalating to parameter fuzzing...")

if __name__ == "__main__":
    asyncio.run(probe_staging_auth())
