import os
from aura.core.storage import AuraStorage
from aura.core.markdown_reporter import MarkdownReporter
from aura.core.platform_reporter import PlatformReporter

db = AuraStorage()

# Insert a dummy SSRF finding with the new proof keys
content = {
    "type": "Blind SSRF",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "payload": "http://169.254.169.254/latest/meta-data/",
    "raw_request": "GET http://test.com/api/proxy?url=http://169.254.169.254/latest/meta-data/\nHost: test.com\nUser-Agent: Aura",
    "proof": "ami-id\nlocal-ipv4\npublic-keys",
    "content": "Aura found a critical SSRF.",
    "evidence_url": "http://test.com/api/proxy"
}

db.add_finding("test.com", content, "Blind SSRF")

# Insert a dummy Secret finding
secret_content = {
    "type": "Exposed Secret: AWS Secret Key",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "secret_value": "AkiaTEST12345/UNREDACTED67890",
    "content": "Exposed AWS Secret Key",
    "evidence_url": "http://test.com/config.js"
}

db.add_finding("test.com", secret_content, "Exposed Secret")

md_r = MarkdownReporter()
md_path = md_r.generate_report(target_filter="test.com")
print(f"Markdown generated at: {md_path}")

pl_r = PlatformReporter()
h1_path = pl_r.generate_hackerone(target_filter="test.com")
print(f"HackerOne generated at: {h1_path}")

print("Printing HackerOne snippet:")
with open(h1_path, "r") as f:
    print(f.read())
