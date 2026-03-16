import asyncio
import re
import aiohttp
from typing import List, Dict, Any
from rich.console import Console
import xml.etree.ElementTree as ET
from aura.core.storage import AuraStorage
from aura.core.brain import AuraBrain

console = Console()

class AuraCloudRecon:
    """
    v15.0: THE CLOUD PREDATOR
    Automated Discovery of Leaky Buckets & Cloud Assets (v19.4: Full async rewrite)
    """
    def __init__(self, storage: AuraStorage):
        self.storage = storage
        self.brain = AuraBrain()
        self.secret_patterns = {
            "AWS Key": r"AKIA[A-Z0-9]{16}",
            "AWS Secret": r"wJalrXUtnFEMI/K7MDENG/bPxRfiCY[a-zA-Z0-9+/]{8}", # Generic pattern
            "Private Key": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
            "General API Key": r"(?i)(api_key|secret|token|password|pw)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]"
        }

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
                            await self._inspect_bucket(url, domain, "AWS S3 Bucket")
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
                            await self._inspect_bucket(url, domain, "GCP Bucket")
                except Exception:
                    pass

    async def _inspect_bucket(self, url: str, domain: str, asset_type: str):
        """Deeply audits a public bucket for sensitive files and secrets."""
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    files = self._parse_s3_xml(resp.text)
                    console.print(f"[green]  [+] {asset_type} listable: {len(files)} files discovered.[/green]")
                    
                    # Target top 20 files for secret scanning (focusing on .env, .git, config, backup)
                    targets = [f for f in files if any(ext in f.lower() for ext in ['.env', '.git', 'config', 'backup', 'secret', 'key', '.sql', '.yaml', '.json'])]
                    
                    for f_key in targets[:10]:
                        f_url = f"{url}/{f_key}" if not url.endswith('/') else f"{url}{f_key}"
                        await self._scan_file_for_secrets(f_url, domain)
                        
            except Exception as e:
                pass

    async def _scan_file_for_secrets(self, file_url: str, domain: str):
        """Scans a specific file for high-entropy secrets and patterns."""
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            try:
                # Use Range header to only pull first 512KB for performance
                resp = await client.get(file_url, headers={"Range": "bytes=0-512000"})
                if resp.status_code in [200, 206]:
                    content = resp.text
                    for name, pattern in self.secret_patterns.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            evidence = f"LEAKED SECRET [{name}] found in {file_url}"
                            console.print(f"[bold red][!] {evidence}[/bold red]")
                            self.storage.add_finding(
                                target_value=domain,
                                content=evidence,
                                finding_type="Cloud Secret Exposure",
                                proof=f"Match: {matches[0]}..."
                            )
            except:
                pass

    def _parse_s3_xml(self, xml_content: str) -> List[str]:
        """Parses S3 XML and returns a list of file keys."""
        files = []
        try:
            root = ET.fromstring(xml_content)
            # Support both namespaced and non-namespaced XML
            ns_url = 'http://s3.amazonaws.com/doc/2006-03-01/'
            ns = {'s3': ns_url}
            
            # Try with namespace
            items = root.findall('.//s3:Contents', ns)
            if not items:
                # Try without namespace
                items = root.findall('.//Contents')
                
            for content in items:
                # Handle cases with and without prefix
                key_node = content.find('s3:Key', ns) if items and 's3' in ns else content.find('Key')
                if key_node is not None:
                    files.append(key_node.text)
        except:
            pass
        return files

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
