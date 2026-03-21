import asyncio
import httpx
from aura.ui.formatter import console

class BucketHunter:
    def __init__(self):
        self.suffixes = [
            "prod", "dev", "staging", "uat", "test", "backups", "logs",
            "data", "internal", "public", "assets", "static", "db", "sql"
        ]
        self.providers = [
            ".s3.amazonaws.com",
            ".s3-us-west-1.amazonaws.com",
            ".s3-ap-southeast-1.amazonaws.com",
            ".storage.googleapis.com"
        ]
        self.hits = []

    async def check_bucket(self, client, bucket_name, provider):
        url = f"https://{bucket_name}{provider}"
        try:
            r = await client.get(url, timeout=5)
            # 200 OK = Publicly Listable (HUGE)
            # 403 Forbidden = Exists but protected (Moderate)
            # 404 Not Found = Doesn't exist
            if r.status_code == 200:
                if "ListBucketResult" in r.text or "Items" in r.text:
                    console.print(f"  [bold red][!!!] OPEN BUCKET: {url}[/bold red]")
                    self.hits.append({"url": url, "status": "OPEN", "size": len(r.text)})
            elif r.status_code == 403:
                 # Check if the error message confirms existence
                 if "AccessDenied" in r.text:
                     # console.print(f"  [yellow][.] Protected Bucket: {url}[/yellow]")
                     pass
        except: pass

    async def run(self, targets):
        console.print(f"[*] Bucket Hunter: Hunting for orphaned storage for {len(targets)} targets...")
        async with httpx.AsyncClient(verify=False) as client:
            tasks = []
            for t in targets:
                # 1. Base name
                base = t.split(".")[0]
                for prov in self.providers:
                    tasks.append(self.check_bucket(client, base, prov))
                
                # 2. Suffix combinations
                for s in self.suffixes:
                    name = f"{base}-{s}"
                    name2 = f"{base}{s}"
                    for prov in self.providers:
                        tasks.append(self.check_bucket(client, name, prov))
                        tasks.append(self.check_bucket(client, name2, prov))

            await asyncio.gather(*tasks)
        
        console.print(f"\n[bold green][!!] BUCKET HUNT COMPLETE. {len(self.hits)} open buckets found.[/bold green]")

if __name__ == "__main__":
    hunter = BucketHunter()
    targets = ["syfe.com", "coinhako.com", "imoulife.com", "traveloka.com"]
    asyncio.run(hunter.run(targets))
