import asyncio
import httpx
import time
from rich.console import Console
from aura.core import state

console = Console()

class RaceConditionHunter:
    """
    ELITE LOGIC: Race Condition (HTTP/2 Turbo)
    Blasts 50+ simultaneous requests using HTTP/2 multiplexing for state-changing endpoints
    (e.g., /api/payments, /api/coupons, /checkout).
    """
    def __init__(self, session=None):
        self.session = session
        
    async def _blast_endpoint(self, url: str, method: str, data: dict, headers: dict) -> list[dict]:
        """Sends a high-concurrency burst of requests over HTTP/2."""
        findings = []
        # HTTP/2 multiplexing client
        async with httpx.AsyncClient(http2=True, verify=False) as client:
            console.print(f"[bold red][⚡ HTTP/2 TURBO] Blasting 50 parallel requests to {url}...[/bold red]")
            
            # Prepare identical requests
            reqs = []
            for _ in range(50):
                if method.upper() == "POST":
                    reqs.append(client.post(url, json=data, headers=headers))
                elif method.upper() == "PUT":
                    reqs.append(client.put(url, json=data, headers=headers))
                else:
                    reqs.append(client.get(url, params=data, headers=headers))

            start_time = time.time()
            responses = await asyncio.gather(*reqs, return_exceptions=True)
            end_time = time.time()
            
            # Analyze responses for race condition success
            success_count = sum(1 for r in responses if isinstance(r, httpx.Response) and r.status_code in [200, 201])
            
            if success_count > 1:
                # If we expect only 1 success (e.g. redeeming a single-use coupon) and got multiple
                findings.append({
                    "type": "Race Condition (Time-of-Check to Time-of-Use)",
                    "severity": "CRITICAL",
                    "cvss_score": 9.1,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    "owasp": "A04:2021-Insecure Design",
                    "mitre": "T1190",
                    "content": (
                        f"Race Condition confirmed on `{url}`.\n"
                        f"Sent 50 simultaneous requests in {(end_time - start_time):.2f}s.\n"
                        f"Server processed {success_count} requests successfully instead of 1."
                    ),
                    "remediation_fix": "Implement strict database row locks (e.g., SELECT ... FOR UPDATE) and atomic operations.",
                    "impact_desc": "Attackers can bypass limits (e.g., spending the same balance multiple times or reusing single-use coupons).",
                    "patch_priority": "IMMEDIATE",
                    "evidence_url": url,
                    "confirmed": True
                })
        return findings

    async def scan_urls(self, discovered_urls: list[str]) -> list[dict]:
        """Filter to state-changing endpoints and run HTTP/2 Turbo."""
        state_changing_kws = ["payment", "coupon", "checkout", "transfer", "redeem", "buy", "vote", "like", "follow"]
        targets = [u for u in discovered_urls if any(kw in u.lower() for kw in state_changing_kws)]
        
        if not targets:
            console.print("[dim][Race] No state-changing endpoints identified for Race Condition testing.[/dim]")
            return []
            
        all_findings = []
        for url in targets:
            # We would normally extract expected params/body from the crawl map. For now, we simulate.
            dummy_data = {"amount": 100, "action": "submit"}
            dummy_headers = {"Authorization": "Bearer TEST"}
            res = await self._blast_endpoint(url, "POST", dummy_data, dummy_headers)
            all_findings.extend(res)
            
        return all_findings
