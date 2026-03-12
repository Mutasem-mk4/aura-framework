import os
import re
import json
import zipfile
import subprocess
from rich.console import Console

console = Console()

class MobileAnalyzer:
    """
    [MOBILE GHOST HUNTER] v38.0: Mobile App Deconstructor.
    Ingests .IPA (iOS) and .APK (Android) files to extract hardcoded secrets.
    """
    def __init__(self, app_path: str):
        self.app_path = app_path
        self.secrets = []
        self.internal_urls = []
        
    async def run(self):
        if not os.path.exists(self.app_path):
            console.print(f"[bold red][!] Mobile App not found: {self.app_path}[/bold red]")
            return []
            
        console.print(f"[bold cyan][⚔️ MOBILE ANALYZER] Deconstructing {os.path.basename(self.app_path)}...[/bold cyan]")
        
        ext = os.path.splitext(self.app_path)[1].lower()
        if ext == ".ipa":
            await self._analyze_ipa()
        elif ext == ".apk":
            await self._analyze_apk()
        else:
            console.print(f"[red][!] Unsupported mobile format: {ext}[/red]")
            
        return self._format_findings()

    async def _analyze_ipa(self):
        """Unzips IPA and searches for Plist and Binary secrets."""
        try:
            with zipfile.ZipFile(self.app_path, 'r') as zip_ref:
                # Search for strings in all files (regex for keys/urls)
                for file_info in zip_ref.infolist():
                    if file_info.file_size > 10000000: continue # Skip huge assets
                    with zip_ref.open(file_info) as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        self._extract_from_text(content, file_info.filename)
        except Exception as e:
            console.print(f"[red][!] IPA analysis failed: {e}[/red]")

    async def _analyze_apk(self):
        """
        Decompiles APK and searches for Java/Native secrets.
        Note: Requires dex2jar/procyon in a real environment.
        """
        console.print("[yellow][*] APK Detected: Performing forensic string extraction...[/yellow]")
        # Mocking the decompilation for now, using deep string search
        try:
            with zipfile.ZipFile(self.app_path, 'r') as zip_ref:
                for file_info in zip_ref.infolist():
                    with zip_ref.open(file_info) as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        self._extract_from_text(content, file_info.filename)
        except Exception as e:
            console.print(f"[red][!] APK analysis failed: {e}[/red]")

    def _extract_from_text(self, text: str, source: str):
        # 1. API Keys / Secrets
        key_patterns = [
            r'(?i)(api[_-]?key|secret|token|auth|password|credential)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_=]{16,})["\']?',
            r'AIza[0-9A-Za-z-_]{35}', # Google API Key
            r'sk_[live|test]_[0-9a-zA-Z]{24}', # Stripe
            r'sq0csp-[0-9A-Za-z\-_]{43}', # Square
        ]
        
        for pattern in key_patterns:
            matches = re.finditer(pattern, text)
            for m in matches:
                secret = m.group(0)
                if secret not in self.secrets:
                    self.secrets.append({"secret": secret, "source": source})

        # 2. Internal / Staging URLs
        url_patterns = [
            r'https?://(?:staging|dev|internal|api-dev|beta|qa|test)\.[a-zA-Z0-9\-\.]+\.[a-z]{2,}',
            r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?::[0-9]+)?'
        ]
        
        for pattern in url_patterns:
            matches = re.finditer(pattern, text)
            for m in matches:
                url = m.group(0)
                if url not in self.internal_urls:
                    self.internal_urls.append({"url": url, "source": source})

    def _format_findings(self):
        findings = []
        if self.secrets:
            console.print(f"[bold red][🔥 SECRETS FOUND] Extracted {len(self.secrets)} hardcoded credentials![/bold red]")
            for s in self.secrets:
                findings.append({
                    "type": "Hardcoded Mobile Secret",
                    "severity": "HIGH",
                    "content": f"Found in {s['source']}: {s['secret']}"
                })
        
        if self.internal_urls:
            console.print(f"[bold yellow][🔗 INTERNAL URLS] Discovered {len(self.internal_urls)} staging/internal endpoints.[/bold yellow]")
            for u in self.internal_urls:
                findings.append({
                    "type": "Hidden Mobile Backend Discovered",
                    "severity": "MEDIUM",
                    "content": f"Found in {u['source']}: {u['url']}"
                })
        return findings
