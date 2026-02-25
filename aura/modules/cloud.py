import requests
import xml.etree.ElementTree as ET
from rich.console import Console

console = Console()

class CloudHunter:
    """Specialized engine for discovering and auditing cloud infrastructure (S3, Azure, GCP)."""
    
    S3_URL_PATTERN = "http://{bucket}.s3.amazonaws.com"
    
    def scan_s3(self, domain):
        """Discovers and checks S3 buckets related to a domain."""
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
                # We check the bucket root
                response = requests.get(url, timeout=5)
                
                # AWS S3 Status Codes:
                # 200: Publicly Listable (GOLD MINE)
                # 403: Exists but Access Denied (Still useful target for other attacks)
                # 404: Doesn't exist
                
                if response.status_code == 200:
                    console.print(f"[bold red][!!!] PUPLIC S3 BUCKET FOUND: {url}[/bold red]")
                    # Try to parse XML to count files
                    file_count = 0
                    try:
                        root = ET.fromstring(response.text)
                        # S3 XML uses namespaces
                        ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
                        file_count = len(root.findall('.//s3:Contents', ns))
                    except:
                        pass
                        
                    found_buckets.append({
                        "name": bucket,
                        "url": url,
                        "status": "PUBLIC",
                        "files_indexed": file_count
                    })
                elif response.status_code == 403:
                    found_buckets.append({
                        "name": bucket,
                        "url": url,
                        "status": "PRIVATE (Access Denied)",
                        "files_indexed": 0
                    })
                    
            except Exception as e:
                continue
                
        return found_buckets

    def estimate_cloud_bounty(self, bucket_info):
        """Estimates bounty value for cloud misconfigurations."""
        if bucket_info["status"] == "PUBLIC" and bucket_info["files_indexed"] > 0:
            return 2500 # High impact
        elif bucket_info["status"] == "PUBLIC":
            return 1000 # Empty but listable
        return 0
