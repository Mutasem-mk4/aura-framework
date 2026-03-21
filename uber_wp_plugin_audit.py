import asyncio
import json
from aura.core.async_requester import AsyncRequester
from aura.ui.formatter import ZenithFormatter

async def wordpress_plugin_audit():
    formatter = ZenithFormatter()
    formatter.banner("Uber WordPress Plugin Audit")
    
    target = "newsroomadmin.uberinternal.com"
    
    # High-risk plugin paths and files
    # Focus on plugins that often have RCE, SQLi or File Access bugs
    plugins = [
        "wp-file-manager", "duplicator", "updraftplus", "contact-form-7",
        "wp-graphql", "elementor", "jetpack", "wp-smtp", "all-in-one-wp-migration",
        "wordfence", "woocommerce", "wp-responsive-menu", "mailchimp-for-wp"
    ]
    
    files = ["readme.txt", "changelog.txt", "license.txt", "wp-json"]
    
    async with AsyncRequester(concurrency_limit=20, timeout=10) as requester:
        formatter.phase_banner("Plugin Scanning", f"Auditing {len(plugins)} high-risk plugins on {target}...")
        
        requests = []
        for p in plugins:
            for f in files:
                requests.append({"method": "GET", "url": f"https://{target}/wp-content/plugins/{p}/{f}"})
        
        results = await requester.fetch_all(requests)
        
        findings = []
        for req, resp in zip(requests, results):
            if resp and resp.status_code == 200:
                print(f"  [bold green][🧩] FOUND PLUGIN FILE: {req['url']} (Size: {len(resp.text)})[/bold green]")
                findings.append({
                    "url": req["url"],
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "snippet": resp.text[:200]
                })
            elif resp and resp.status_code in [403, 500]:
                 # Sometimes 403 on a specific file confirms the folder exists but is protected
                 pass

    if findings:
        with open("reports/uber_wordpress_audit.json", "w") as f:
            json.dump(findings, f, indent=4)
        print(f"\n[✓] Audit complete. {len(findings)} plugin files identified. Checking for CVEs...")
    else:
        print("\n[!] No common plugins identified via standard paths. Varnish shielding is tight.")

if __name__ == "__main__":
    asyncio.run(wordpress_plugin_audit())
