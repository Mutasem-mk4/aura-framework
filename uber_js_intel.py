import asyncio
import re
import json
import urllib.parse
from aura.core.async_requester import AsyncRequester
from aura.ui.formatter import ZenithFormatter

async def extract_js_intelligence():
    formatter = ZenithFormatter()
    formatter.banner("Uber Deep JS Intelligence")
    
    targets = ["https://auth.uber.com", "https://api.uber.com", "https://www.uber.com"]
    js_files = set()
    
    async with AsyncRequester(concurrency_limit=10, timeout=15) as requester:
        formatter.phase_banner("JS Discovery", "Fetching script sources from landing pages...")
        
        for target in targets:
            try:
                resp = await requester.fetch("GET", target, follow_redirects=True)
                if resp and resp.status_code == 200:
                    found = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
                    for src in found:
                        full_url = urllib.parse.urljoin(target, src)
                        if "uber.com" in full_url:
                            js_files.add(full_url)
            except Exception as e:
                print(f"  [dim]Discovery failed for {target}: {e}[/dim]")
        
        if not js_files:
            print("\n[!] No JS files discovered on landing pages.")
            return

        formatter.phase_banner("Secret Mining", f"Analyzing {len(js_files)} discovered bundles...")
        
        # Search patterns for secrets and endpoints
        patterns = {
            "API_KEY": r'["\']([^"\']*(?:api|secret|key|token)[^"\']*(?:[a-zA-Z0-9]{32,}))["\']',
            "INTERNAL_URL": r'["\'](https?://[^"\']*(?:internal|corp|staging|dev)[^"\']*)["\']',
            "GRAPHQL_QUERY": r'(?:query|mutation)\s*\{'
        }
        
        findings = []
        for js_url in js_files:
            try:
                resp = await requester.fetch("GET", js_url)
                if resp and resp.status_code == 200:
                    content = resp.text
                    for name, regex in patterns.items():
                        matches = re.findall(regex, content, re.IGNORECASE)
                        for m in matches:
                            findings.append({
                                "type": name,
                                "source": js_url,
                                "value": m[:100] # Truncate for display
                            })
                            print(f"  [bold cyan]✨ Found {name} in {js_url.split('/')[-1]}[/bold cyan]")
            except Exception:
                pass

    if findings:
        with open("reports/uber_js_intelligence.json", "w") as f:
            json.dump(findings, f, indent=4)
        print(f"\n[✓] JS intelligence complete. {len(findings)} potential secrets/endpoints found.")
    else:
        print("\n[!] No sensitive metadata discovered in public JS bundles.")

if __name__ == "__main__":
    asyncio.run(extract_js_intelligence())
