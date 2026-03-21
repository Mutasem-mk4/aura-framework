import asyncio
import httpx
import re
from bs4 import BeautifulSoup
from aura.ui.formatter import console

async def extract_buckets(url):
    console.print(f"[*] Fetching JS bundles from {url}...")
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            r = await client.get(url)
            soup = BeautifulSoup(r.text, 'html.parser')
            js_urls = [s.get('src') for s in soup.find_all('script') if s.get('src') and s.get('src').endswith('.js')]
            
            buckets = set()
            for js in js_urls:
                full_js_url = js if js.startswith('http') else (url.rstrip('/') + (js if js.startswith('/') else '/' + js))
                console.print(f"  [.] Inspecting: {full_js_url}")
                try:
                    js_r = await client.get(full_js_url)
                    # S3 bucket regex
                    s3_matches = re.findall(r'([a-z0-9.-]+\.s3\.amazonaws\.com)', js_r.text)
                    # Firebase regex
                    fb_matches = re.findall(r'([a-z0-9.-]+\.firebaseio\.com)', js_r.text)
                    # Generic bucket name patterns
                    bucket_patterns = re.findall(r'[\"\'`]([a-z0-9.-]+-bucket-[a-z0-9.-]+)[\"\'`]', js_r.text)
                    
                    for m in s3_matches + fb_matches + bucket_patterns:
                        buckets.add(m)
                except Exception: pass
            
            if buckets:
                console.print(f"\n[bold green][!!] Found {len(buckets)} Potential Cloud Storage Identifiers:[/bold green]")
                for b in buckets:
                    console.print(f"  -> {b}")
                return list(buckets)
            else:
                console.print("  [yellow][.] No cloud storage identifiers found in main bundles.[/yellow]")
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")
    return []

async def verify_bucket_access(bucket_url):
    # Construct the base S3 list URL if it's just a bucket name
    test_url = bucket_url if bucket_url.startswith('http') else f"https://{bucket_url}"
    console.print(f"[*] Testing Public Access -> {test_url}")
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            r = await client.get(test_url)
            if r.status_code == 200:
                if "ListBucketResult" in r.text or "Contents" in r.text:
                    console.print(f"  [bold red][!!!] PUBLIC S3 BUCKET EXPOSURE: {test_url}[/bold red]")
                    return True
            elif r.status_code == 403:
                # console.print(f"  [.] {test_url} -> Access Denied (Secure)")
                pass
    except Exception: pass
    return False

async def run_redemption():
    targets = ["https://www.traveloka.com", "https://api-au.syfe.com"]
    for t in targets:
        buckets = await extract_buckets(t)
        for b in buckets:
            await verify_bucket_access(b)

if __name__ == "__main__":
    asyncio.run(run_redemption())
