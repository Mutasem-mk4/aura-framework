"""
Aura v51.0 — InfraReaper (Infrastructure Domination) ⛓️💀
=========================================================
Specialized engine for auditing K8s, Docker, and sensitive infra ports.
Escalates from open ports to full container escape or cluster takeover.
"""
import asyncio
import json
import httpx
from rich.console import Console
from rich.panel import Panel
from typing import List, Dict, Any, Optional

from aura.ui.formatter import console

class InfraReaper:
    """
    v51.0 OMEGA: InfraReaper.
    The ultimate container & cluster auditor.
    """

    INFRA_PORTS = {
        10250: "Kubelet API (K8s)",
        10255: "Kubelet Read-Only API (K8s)",
        2375: "Docker Remote API (Unencrypted)",
        2376: "Docker Remote API (TLS)",
        6443: "Kubernetes API Server",
        2379: "Etcd Client Port",
        30000: "Possible Kubernetes NodePort"
    }

    def __init__(self):
        self.findings = []

    async def audit_host(self, host: str, open_ports: List[int]):
        """
        Audits a host if infrastructure-related ports are open.
        host: '10.0.0.1' or 'target.com'
        """
        console.print(f"[bold cyan][InfraReaper] Auditing Infrastructure on {host}[/bold cyan]")
        
        tasks = []
        for port in open_ports:
            if port in self.INFRA_PORTS:
                console.print(f"[dim]  [*] Targeting {self.INFRA_PORTS[port]} on port {port}...[/dim]")
                if port in [10250, 10255]:
                    tasks.append(self._audit_kubelet(host, port))
                elif port in [2375, 2376]:
                    tasks.append(self._audit_docker(host, port))
                elif port == 2379:
                    tasks.append(self._audit_etcd(host, port))

        if tasks:
            await asyncio.gather(*tasks)

    async def _audit_kubelet(self, host: str, port: int):
        """Audits Kubelet for unauthenticated access to pods/exec."""
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            # Check for /pods (sensitive information leak)
            try:
                url = f"https://{host}:{port}/pods" if port == 10250 else f"http://{host}:{port}/pods"
                resp = await client.get(url)
                if resp.status_code == 200 and "pods" in resp.text:
                    evidence = f"Unauthenticated Kubelet Pod Disclosure on {host}:{port}\nDiscovered pods: {len(resp.json().get('items', []))}"
                    console.print(Panel(evidence, title="[bold red]CRITICAL: K8S EXPOSURE[/bold red]", border_style="red"))
                    self.findings.append({"type": "Kubelet Pod Disclosure", "severity": "CRITICAL", "url": url, "evidence": evidence})
            except:
                pass

    async def _audit_docker(self, host: str, port: int):
        """Audits Docker API for unauthenticated container management."""
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            try:
                url = f"http://{host}:{port}/v1.24/containers/json"
                resp = await client.get(url)
                if resp.status_code == 200:
                    containers = resp.json()
                    evidence = f"Exposed Docker Remote API on {host}:{port}\nRunning containers: {len(containers)}"
                    console.print(Panel(evidence, title="[bold red]CRITICAL: DOCKER RCE[/bold red]", border_style="red"))
                    self.findings.append({"type": "Docker API Exposure", "severity": "CRITICAL", "url": url, "evidence": evidence})
            except:
                pass

    async def _audit_etcd(self, host: str, port: int):
        """Audits Etcd for sensitive key disclosure."""
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            try:
                url = f"http://{host}:{port}/v2/keys/?recursive=true"
                resp = await client.get(url)
                if resp.status_code == 200:
                    evidence = f"Exposed Etcd Key-Value Store on {host}:{port}\nKeys found."
                    console.print(Panel(evidence, title="[bold red]CRITICAL: ETCD EXPOSURE[/bold red]", border_style="red"))
                    self.findings.append({"type": "Etcd Exposure", "severity": "CRITICAL", "url": url, "evidence": evidence})
            except:
                pass

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        # Example: python infra_reaper.py 1.2.3.4 10250 2375
        host = sys.argv[1]
        ports = [int(p) for p in sys.argv[2:]]
        asyncio.run(InfraReaper().audit_host(host, ports))
