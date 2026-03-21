import asyncio
import httpx
from bs4 import BeautifulSoup
import re
from aura.ui.formatter import console

async def extract_api_from_js():
    url = "https://indorse.io"
    console.print(f"[*] Fetching {url}...")
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            r = await client.get(url)
            soup = BeautifulSoup(r.text, 'html.parser')
            js_urls = []
            
            # Find embedded scripts too, maybe they have endpoints
            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    if src.startswith('http'):
                        js_urls.append(src)
                    elif src.startswith('/'):
                        js_urls.append(url + src)
                    else:
                        js_urls.append(url + '/' + src)
                else:
                    # check inline script content
                    content = script.string
                    if content:
                        endpoints = re.findall(r'[\"\'\`]((?:/|https?://)[^\s\"\'\`]+)[\"\'\`]', content)
                        for ep in endpoints:
                             if 'api' in ep.lower() or 'graphql' in ep.lower() or 'v1' in ep.lower():
                                  console.print(f"  [+] Found inline: {ep}")

            # Now fetch all external scripts
            api_endpoints = set()
            for js_url in set(js_urls):
                console.print(f"[*] Fetching JS: {js_url}")
                try:
                    js_r = await client.get(js_url)
                    if js_r.status_code == 200:
                        content = js_r.text
                        endpoints = re.findall(r'[\"\'\`]((?:/|https?://)[^\s\"\'\`><{}]+)[\"\'\`]', content)
                        for ep in endpoints:
                            if 'api' in ep.lower() or 'graphql' in ep.lower() or 'v1' in ep.lower() or 'v2' in ep.lower() or 'user' in ep.lower() or 'profile' in ep.lower():
                                if len(ep) > 5 and len(ep) < 100:
                                    api_endpoints.add(ep)
                except Exception as e:
                    console.print(f"  [!] Error fetching {js_url}: {e}")
                    
            console.print(f"\n[bold green][!!] API MAPPING COMPLETE. Found {len(api_endpoints)} unique endpoints:[/bold green]")
            for ep in sorted(list(api_endpoints)):
                console.print(f"  -> {ep}")
                
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")

if __name__ == "__main__":
    asyncio.run(extract_api_from_js())
