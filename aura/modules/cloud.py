import requests
import xml.etree.ElementTree as ET
from rich.console import Console
from aura.core.stealth import StealthEngine, AuraSession

console = Console()

stealth = StealthEngine()
session = AuraSession(stealth)

class CloudHunter:
    """Specialized engine for discovering and auditing cloud infrastructure (S3, Azure, GCP)."""
    
    S3_URL_PATTERN = "http://{bucket}.s3.amazonaws.com"
    
    async def scan_s3(self, domain):
        """Discovers and checks S3 buckets related to a domain with network throttling."""
        # Common bucket naming permutations
        permutations = [
            domain,
            f"staging-{domain}",
            f"dev-{domain}",
            f"{domain}-backup",
            f"{domain}-data",
            f"{domain}-assets",
            domain.replace(".", "-")
        ]
        
        found_buckets = []
        console.print(f"[bold yellow][*] CloudHunter: Hunting for S3 buckets related to {domain}...[/bold yellow]")
        
        for bucket in permutations:
            url = self.S3_URL_PATTERN.format(bucket=bucket)
            try:
                # Using throttled AuraSession for system stability
                response = await session.get(url, timeout=5)
                
                # AWS S3 Status Codes:
                # 200: Publicly Listable (GOLD MINE)
                # 403: Exists but Access Denied (Still useful target for other attacks)
                # 404: Doesn't exist
                
                if response.status_code == 200:
                    console.print(f"[bold red][!!!] PUBLIC S3 BUCKET FOUND: {url}[/bold red]")
                    
                    found_files = self._inspect_bucket_files(response.text)
                    file_count = len(found_files)
                    
                    # Highlight sensitive files
                    sensitive_hits = [f for f in found_files if any(ext in f.lower() for ext in ['.env', '.git', 'backup', 'secret', 'key', 'config', 'sql'])]
                    if sensitive_hits:
                        console.print(f"[bold yellow][!] Sensitive files found in {bucket}: {', '.join(sensitive_hits[:5])}...[/bold yellow]")

                    found_buckets.append({
                        "name": bucket,
                        "url": url,
                        "status": "PUBLIC",
                        "files_indexed": file_count,
                        "sensitive_files": sensitive_hits
                    })
                elif response.status_code == 403:
                    found_buckets.append({
                        "name": bucket,
                        "url": url,
                        "status": "PRIVATE (Access Denied)",
                        "files_indexed": 0,
                        "sensitive_files": []
                    })
                    
            except Exception as e:
                continue
                
        return found_buckets

    def _inspect_bucket_files(self, xml_content):
        """Parses S3 XML and returns a list of file keys."""
        files = []
        try:
            root = ET.fromstring(xml_content)
            ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
            for content in root.findall('.//s3:Contents', ns):
                key = content.find('s3:Key', ns)
                if key is not None:
                    files.append(key.text)
        except:
            pass
        return files

    def estimate_cloud_bounty(self, bucket_info):
        """Estimates bounty value for cloud misconfigurations."""
        if bucket_info["status"] == "PUBLIC" and bucket_info["files_indexed"] > 0:
            return 2500 # High impact
        elif bucket_info["status"] == "PUBLIC":
            return 1000 # Empty but listable
        return 0
