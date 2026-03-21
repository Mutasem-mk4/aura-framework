import asyncio
import httpx
import re
from aura.ui.formatter import console

async def find_emails_in_env(url):
    console.print(f"[*] Searching for administrative contacts in .env -> {url}")
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            r = await client.get(url)
            if r.status_code == 200:
                content = r.text
                # Look for email patterns
                emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", content)
                if emails:
                    unique_emails = list(set(emails))
                    console.print(f"  [bold green][!!] FOUND EMAILS:[/bold green]")
                    for e in unique_emails:
                        console.print(f"    -> {e}")
                else:
                    console.print(f"  [yellow][.] No clear email addresses found in .env text.[/yellow]")
                
                # Look for specific mail variables
                mail_vars = ["MAIL_FROM", "ADMIN_EMAIL", "SES_EMAIL", "SENDGRID_EMAIL"]
                for v in mail_vars:
                    if v in content:
                        match = re.search(f"{v}=(.*?)$", content, re.MULTILINE)
                        if match:
                            console.print(f"    [!] Found variable {v}: {match.group(1)}")
            else:
                console.print(f"  [red][!] Failed to read .env: {r.status_code}[/red]")
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")

if __name__ == "__main__":
    asyncio.run(find_emails_in_env("https://indorse.io/.env"))
