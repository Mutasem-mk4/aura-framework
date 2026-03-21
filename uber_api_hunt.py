import asyncio
import json
import os
from aura.modules.recon_engine import ReconEngine
from aura.core.async_requester import AsyncRequester
from aura.ui.formatter import ZenithFormatter

async def hunt_api_schema():
    formatter = ZenithFormatter()
    formatter.banner("Uber API Schema Hunt")
    
    targets = [
        "api.uber.com",
        "mobile-api.uber.com",
        "v1-mobile.uber.com",
        "business.uber.com",
        "accounts.uber.com"
    ]
    
    paths = [
        "/graphql",
        "/api/graphql",
        "/v1/swagger.json",
        "/v2/api-docs",
        "/swagger-ui.html",
        "/v1/me",
        "/v1/profile",
        "/api/v1/auth/mfa/verify",
        "/.well-known/openid-configuration"
    ]
    
    async with AsyncRequester(concurrency_limit=20, timeout=10) as requester:
        formatter.phase_banner("Schema Probing", f"Testing {len(targets) * len(paths)} endpoints...")
        
        requests = []
        for t in targets:
            for p in paths:
                requests.append({"method": "GET", "url": f"https://{t}{p}", "meta": {"target": t, "path": p}})
        
        results = await requester.fetch_all(requests)
        
        findings = []
        for req, resp in zip(requests, results):
            if resp and resp.status_code in [200, 401, 403]:
                # 401/403 are also interesting because they confirm the endpoint exists
                info = {
                    "target": req["meta"]["target"],
                    "path": req["meta"]["path"],
                    "status": resp.status_code,
                    "length": len(resp.text)
                }
                findings.append(info)
                if resp.status_code == 200:
                    print(f"  [bold green]🔥 Potential Schema Found: {info['target']}{info['path']} (200 OK)[/bold green]")
                elif resp.status_code == 401:
                    print(f"  [yellow]🔒 Authenticated Endpoint: {info['target']}{info['path']} (401 Unauthorized)[/yellow]")

    if findings:
        with open("reports/api_schema_hunt.json", "w") as f:
            json.dump(findings, f, indent=4)
        print(f"\n[✓] Schema hunt complete. Results saved to reports/api_schema_hunt.json")

if __name__ == "__main__":
    asyncio.run(hunt_api_schema())
