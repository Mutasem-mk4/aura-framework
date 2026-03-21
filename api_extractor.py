import asyncio
import httpx
import re
from bs4 import BeautifulSoup

text_output = ""

async def go():
    global text_output
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        try:
            r = await c.get('https://indorse.io')
            soup = BeautifulSoup(r.text, 'html.parser')
            js_urls = [s.get('src') for s in soup.find_all('script') if s.get('src') and s.get('src').endswith('.js')]
            for js in js_urls:
                url = js if js.startswith('http') else ('https://indorse.io' + (js if js.startswith('/') else '/' + js))
                try:
                    js_r = await c.get(url)
                    # any path-like string (e.g., /api/.., /v1/.., /users/)
                    strings = re.findall(r'[\"\'\`]((?:/[a-zA-Z0-9_-]+){2,})[\"\'\`]', js_r.text)
                    res = set(strings)
                    for ep in res:
                        if 'api' in ep.lower() or '/v1/' in ep.lower() or 'user' in ep.lower() or 'profile' in ep.lower():
                            if len(ep) < 80:
                                text_output += ep + "\n"
                except Exception as e:
                    pass
        except Exception as e:
            pass

asyncio.run(go())
print("API Endpoints Extracted:")
for line in set(text_output.split("\n")):
    if line.strip(): print(line)
