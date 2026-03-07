import asyncio
import re
import aiohttp
from rich.console import Console
from aura.core.storage import AuraStorage

console = Console()

class AuraCloudRecon:
    """
    v15.0: THE CLOUD PREDATOR
    Automated Discovery of Leaky Buckets & Cloud Assets (v19.4: Full async rewrite)
    """
    def __init__(self, storage: AuraStorage):
        self.storage = storage

    async def hunt(self, domain: str):
        """Main entry point to scan for cloud assets related to a domain."""
        console.print(f"[bold cyan][*] Cloud Predator: Starting hunt on {domain}[/bold cyan]")
        base_name = domain.split('.')[0]
        seeds = [
            base_name,
            f"{base_name}-data",
            f"{base_name}-backup",
            f"{base_name}-prod",
            f"{base_name}-dev",
            f"{base_name}-staging",
            f"{base_name}-assets",
            f"{base_name}-media",
        ]

        # Run all cloud checks concurrently
        await asyncio.gather(
            self._check_aws_s3(seeds, domain),
            self._check_gcp_buckets(seeds, domain),
            return_exceptions=True
        )
        console.print(f"[dim cyan][*] Cloud Predator: Hunt complete for {domain}[/dim cyan]")

    async def _check_aws_s3(self, seeds: list, domain: str):
        """Check for publicly accessible AWS S3 buckets (async)."""
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            for seed in seeds:
                url = f"https://{seed}.s3.amazonaws.com"
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=7)) as r:
                        if r.status == 200:
                            self._log_cloud_asset(domain, url, "AWS S3 Bucket", "Publicly Accessible (200 OK)")
                        # v22.6: Suppress 403 Private — these are unrelated public AWS buckets
                        # that happen to share a name prefix with the target
                except Exception:
                    pass

    async def _check_gcp_buckets(self, seeds: list, domain: str):
        """Check for Google Cloud Storage Buckets (async)."""
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            for seed in seeds:
                url = f"https://storage.googleapis.com/{seed}"
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=7)) as r:
                        if r.status == 200:
                            self._log_cloud_asset(domain, url, "GCP Bucket", "Publicly Accessible (200 OK)")
                        # v22.6: Suppress 403 Private — unrelated GCP buckets with same prefix
                except Exception:
                    pass

    def _log_cloud_asset(self, domain: str, url: str, asset_type: str, status: str):
        """Logs identified asset to storage."""
        console.print(f"[bold red][!!!] CLOUD ASSET FOUND: [{asset_type}] {url} | {status}[/bold red]")
        try:
            self.storage.log_action(
                action=f"CLOUD_ASSET_FOUND:{asset_type}",
                target=domain,
                details=f"URL={url} Status={status}"
            )
            if "Accessible (200 OK)" in status:
                self.storage.add_finding(
                    target_value=domain,
                    content=f"Exposed {asset_type}: {url}",
                    finding_type="Cloud Security Misconfiguration",
                    proof=f"HTTP 200 on {url}"
                )
        except Exception as e:
            console.print(f"[dim red][!] Cloud storage log error: {e}[/dim red]")
