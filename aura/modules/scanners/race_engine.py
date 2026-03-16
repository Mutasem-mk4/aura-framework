import asyncio
import httpx
import time
from typing import List, Dict, Optional

class RaceEngine:
    """
    Aura v33 Zenith: Race Condition Detection Engine.
    Detects concurrency-based vulnerabilities in financial and stateful transactions.
    """
    
    def __init__(self, concurrency: int = 15):
        self.concurrency = concurrency

    async def _single_race_request(self, client: httpx.AsyncClient, url: str, method: str, data: Optional[Dict], headers: Optional[Dict]):
        try:
            if method.upper() == "POST":
                return await client.post(url, json=data, headers=headers)
            return await client.get(url, headers=headers)
        except:
            return None

    async def check_race(self, url: str, method: str = "POST", data: Optional[Dict] = None, headers: Optional[Dict] = None) -> bool:
        """
        Attempts to trigger a race condition by sending concurrent requests.
        Checks for inconsistent state or multiple success responses where only one is expected.
        """
        async with httpx.AsyncClient() as client:
            tasks = [self._single_race_request(client, url, method, data, headers) for _ in range(self.concurrency)]
            responses = await asyncio.gather(*tasks)
            
            # Analyze responses for 'race' patterns (multiple 200/201s for state-changing ops)
            success_count = len([r for r in responses if r and r.status_code in [200, 201]])
            
            # If we see multiple successes on what should be a one-time action, it's a race
            if success_count > 1 and method.upper() == "POST":
                return True
        return False

    async def run(self, url: str, stateful_endpoints: List[str]) -> List[Dict]:
        """Runs race condition testing on likely vulnerable endpoints (withdraw, transfer, apply)."""
        findings = []
        for endpoint in stateful_endpoints:
            if any(keyword in endpoint.lower() for keyword in ["withdraw", "transfer", "coupon", "redeem", "vote"]):
                if await self.check_race(endpoint):
                    findings.append({
                        "type": "RACE_CONDITION",
                        "severity": "HIGH",
                        "description": f"Potential Race Condition detected on {endpoint}.",
                        "target": url
                    })
        return findings
