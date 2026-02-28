"""
Ghost v5: Business Logic Intelligence Module
AI-driven testing for IDOR, Auth-Bypass, and parameter manipulation.
Thinks like a human hacker: 'If user_id=1 shows data, what about user_id=2?'
"""
import asyncio
import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from rich.console import Console

console = Console()

class BusinessLogicAuditor:
    """
    Ghost v5 AI module that probes for business logic flaws.
    OWASP A01:2021 (Broken Access Control) & A04:2021 (Insecure Design).
    """

    def __init__(self, brain, session):
        self.brain = brain
        self.session = session

    async def test_idor(self, url: str, page_html: str) -> list:
        """
        Tests for Insecure Direct Object Reference (IDOR) vulnerabilities.
        Analyzes URL and page content to identify numeric IDs and tests for cross-user access.
        """
        findings = []
        console.print(f"[bold cyan][🕵️] Ghost v5: Business Logic IDOR test on {url}...[/bold cyan]")

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # AI-driven parameter identification
        idor_candidates = []
        for key, val in params.items():
            if val and (val[0].isdigit() or key.lower() in ["id", "user_id", "account_id", "order_id", "item_id", "doc_id"]):
                idor_candidates.append((key, val[0]))

        # Also check URL path for numeric segments (e.g., /user/123/profile)
        path_segments = [s for s in parsed.path.split("/") if s.isdigit()]
        for seg in path_segments:
            idor_candidates.append(("path_segment", seg))

        if not idor_candidates:
            return []

        console.print(f"[cyan][🔍] Found {len(idor_candidates)} IDOR candidates. Testing cross-object access...[/cyan]")

        for key, orig_val in idor_candidates:
            try:
                # Try adjacent ID values (manipulation test)
                test_vals = [str(int(orig_val) + 1), str(int(orig_val) - 1), "0", "1", "999"]

                for test_val in test_vals:
                    if test_val == orig_val or int(test_val) < 0:
                        continue

                    # Build modified URL
                    if key == "path_segment":
                        test_url = url.replace(f"/{orig_val}/", f"/{test_val}/").replace(f"/{orig_val}", f"/{test_val}")
                    else:
                        new_params = {k: v for k, v in params.items()}
                        new_params[key] = [test_val]
                        new_query = urlencode({k: v[0] for k, v in new_params.items()})
                        test_url = urlunparse(parsed._replace(query=new_query))

                    res = await self.session.get(test_url, timeout=7)

                    if res.status_code == 200 and len(res.text) > 200:
                        # Check if different data is returned (heuristic: different content length)
                        original_res = await self.session.get(url, timeout=7)
                        if abs(len(res.text) - len(original_res.text)) > 50:
                            # Ask AI to confirm if data leakage occurred
                            ai_confirm_prompt = f"""
                            IDOR Test Result Analysis:
                            Original URL: {url} (param {key}={orig_val})
                            Test URL: {test_url} (param {key}={test_val})
                            Original Response Size: {len(original_res.text)} bytes
                            Test Response Size: {len(res.text)} bytes
                            Test Response Snippet: {res.text[:500]}

                            Does the test response show data belonging to a DIFFERENT user/object than expected?
                            Is this an IDOR vulnerability? Reply ONLY with JSON: {{"is_idor": boolean, "evidence": "string"}}
                            """
                            ai_res = self.brain.reason({"task": "verify_idor", "prompt": ai_confirm_prompt})

                            import json
                            try:
                                if "```json" in ai_res: ai_res = ai_res.split("```json")[-1].split("```")[0]
                                ai_data = json.loads(ai_res)
                                if ai_data.get("is_idor"):
                                    console.print(f"[bold red][!!!] GHOST v5 IDOR HIT: {test_url} - {ai_data.get('evidence')}[/bold red]")
                                    findings.append({
                                        "type": "Insecure Direct Object Reference (IDOR)",
                                        "severity": "HIGH",
                                        "cvss_score": 7.5,
                                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                                        "owasp": "A01:2021-Broken Access Control",
                                        "content": f"IDOR Confirmed: Changing {key} from {orig_val} to {test_val} exposes different object data at {test_url}. Evidence: {ai_data.get('evidence')}",
                                        "remediation_fix": "Implement server-side authorization checks for every object access request. Use indirect references (UUID) instead of direct database IDs."
                                    })
                                    break
                            except: pass
            except Exception as e:
                console.print(f"[dim red][!] IDOR test error for {key}: {e}[/dim red]")

        return findings

    async def test_auth_bypass(self, url: str) -> list:
        """
        Tests for authentication bypass by manipulating headers and parameters.
        Uses known bypass techniques.
        """
        findings = []
        bypass_techniques = [
            # Header manipulation
            {"headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}},
            {"headers": {"X-Custom-IP-Authorization": "127.0.0.1"}},
            {"headers": {"X-Originating-IP": "127.0.0.1"}},
            # Parameter techniques
            {"suffix": "?admin=true"},
            {"suffix": "?role=admin"},
        ]

        try:
            original = await self.session.get(url, timeout=5)
            orig_len = len(original.text)

            for technique in bypass_techniques:
                try:
                    test_url = url + technique.get("suffix", "")
                    extra_headers = technique.get("headers", {})
                    res = await self.session.get(test_url, timeout=5, headers=extra_headers)

                    if res.status_code == 200 and abs(len(res.text) - orig_len) > 100:
                        findings.append({
                            "type": "Authentication Bypass",
                            "severity": "CRITICAL",
                            "cvss_score": 9.8,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "owasp": "A07:2021-Identification and Authentication Failures",
                            "content": f"Potential Auth Bypass: {url} responds differently with bypass technique {technique}. Response size changed from {orig_len} to {len(res.text)} bytes.",
                            "remediation_fix": "Never trust client-supplied headers for authorization. Implement strict server-side session validation."
                        })
                except: pass
        except: pass

        return findings

    async def run_full_audit(self, url: str, page_html: str = "") -> list:
        """Runs the full Ghost v5 business logic audit suite on a target URL."""
        all_findings = []

        idor_results = await self.test_idor(url, page_html)
        all_findings.extend(idor_results)

        auth_results = await self.test_auth_bypass(url)
        all_findings.extend(auth_results)

        return all_findings
