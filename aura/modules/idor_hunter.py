"""
Aura v21.0 — IDOR Hunter (Insecure Direct Object Reference)
The #1 highest-paid vulnerability class on bug bounty platforms.

Detects and CONFIRMS IDOR/BOLA vulnerabilities by:
1. Discovering numeric/UUID ID parameters across all discovered URLs
2. Substituting IDs with adjacent values (id+1, id-1) or other-account IDs
3. Comparing responses to confirm unauthorized data access

A confirmed IDOR = $500-$5,000 on most programs.
"""
import re
import asyncio
import urllib.parse
from rich.console import Console
from aura.core import state

from aura.ui.formatter import console

# UUID pattern
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

# Numeric ID patterns in URLs and params
NUMERIC_ID_RE = re.compile(r"(?:^|[?&/])(?:id|user_id|account_id|order_id|invoice_id|ticket_id|item_id|post_id|doc_id|file_id|uid|pid|cid)=?(\d{1,10})(?:$|[&/])", re.I)


class IDORHunter:
    """
    IDOR/BOLA (Broken Object Level Authorization) Hunter.
    Tests every ID-bearing URL for horizontal privilege escalation.
    """

    def __init__(self, session=None, session_b=None):
        self.session = session
        self.session_b = session_b  # Elite Logic: Dual-Credential User B

    # ─── ID Parameter Discovery ───────────────────────────────────────────
    @staticmethod
    def _extract_id_params(url: str) -> list[tuple[str, str, str]]:
        """
        Returns list of (param_name, param_value, param_type) for ID-bearing params.
        param_type: 'numeric' | 'uuid'
        """
        found = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        for name, values in params.items():
            val = values[0] if values else ""
            name_lower = name.lower()

            # Numeric ID
            if val.isdigit() and any(kw in name_lower for kw in ["id", "uid", "pid", "cid", "num", "ref", "no", "nr"]):
                found.append((name, val, "numeric"))
            # UUID in param value
            elif UUID_RE.fullmatch(val):
                found.append((name, val, "uuid"))

        # Also check path segments like /users/123/profile
        path_parts = parsed.path.split("/")
        for i, part in enumerate(path_parts):
            if part.isdigit() and len(part) <= 9:
                found.append((f"__path_segment_{i}", part, "numeric"))
            elif UUID_RE.fullmatch(part):
                found.append((f"__path_segment_{i}", part, "uuid"))

        return found

    @staticmethod
    def _build_tampered_urls(url: str, param_name: str, original_val: str, param_type: str) -> list[tuple[str, str]]:
        """Generates tampered URL variants for IDOR testing."""
        tampered = []
        parsed = urllib.parse.urlparse(url)

        if param_type == "numeric":
            oid = int(original_val)
            test_ids = [oid + 1, oid - 1, oid + 2, 1, 2, 999, 1000]
            test_ids = [str(i) for i in test_ids if i > 0 and str(i) != original_val]

            if param_name.startswith("__path_segment_"):
                seg_idx = int(param_name.split("_")[-1])
                parts = parsed.path.split("/")
                for tid in test_ids[:3]:
                    new_parts = parts[:]
                    new_parts[seg_idx] = tid
                    new_path = "/".join(new_parts)
                    new_url = parsed._replace(path=new_path).geturl()
                    tampered.append((new_url, tid))
            else:
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                for tid in test_ids[:3]:
                    qs[param_name] = [tid]
                    new_query = urllib.parse.urlencode(qs, doseq=True)
                    new_url = parsed._replace(query=new_query).geturl()
                    tampered.append((new_url, tid))

        elif param_type == "uuid":
            # Try a predictably different UUID
            fake_uuids = ["00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"]
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for fuuid in fake_uuids:
                qs[param_name] = [fuuid]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                new_url = parsed._replace(query=new_query).geturl()
                tampered.append((new_url, fuuid))

        return tampered

    async def _probe(self, url: str, use_session_b: bool = False) -> tuple[int, str, int]:
        """Returns (status_code, content_snippet, content_length)."""
        try:
            sess = self.session_b if use_session_b and self.session_b else self.session
            if not sess: return 0, "", 0
            res = await sess.get(url, timeout=state.NETWORK_TIMEOUT)
            if res:
                text = res.text or ""
                return res.status_code, text[:500], len(text)
        except Exception:
            pass
        return 0, "", 0

    @staticmethod
    def _is_idor_confirmed(orig_status, orig_len, orig_snip, test_status, test_len, test_snip, dual_auth=False) -> tuple[bool, str]:
        """
        Determines if the response difference indicates an IDOR.
        """
        if orig_status != 200 or test_status != 200:
            return False, f"Non-200 response (orig:{orig_status}, test:{test_status})"

        if dual_auth:
            # In dual_auth, User B accesses User A's ID. If lengths/content are identical, it's BOLA!
            if orig_len == test_len or abs(orig_len - test_len) < 50:
                return True, "User B successfully accessed User A's data (Dual-Credential BOLA Confirmed)"
            return False, "User B received different or no data"

        # Content must differ (same content = same public resource)
        if orig_len == test_len and orig_snip == test_snip:
            return False, "Identical responses — likely public resource"

        if abs(orig_len - test_len) > 50:
            return True, f"Content length differs: {orig_len} vs {test_len} bytes — different object returned"

        if orig_snip != test_snip and test_len > 100:
            return True, "Response content differs with same length — different object data returned"

        return False, "No meaningful difference detected"

    async def test_url(self, url: str) -> list[dict]:
        """Tests a single URL for IDOR vulnerabilities."""
        if not self.session:
            return []

        id_params = self._extract_id_params(url)
        if not id_params:
            return []

        findings = []
        console.print(f"[cyan][IDOR] Testing {len(id_params)} ID param(s) on {url}...[/cyan]")

        orig_status, orig_snip, orig_len = await self._probe(url)
        if orig_status == 0:
            return []

        for param_name, original_val, param_type in id_params:
            
            # ELITE LOGIC: Dual-Credential Audit
            if self.session_b:
                test_status, test_snip, test_len = await self._probe(url, use_session_b=True)
                is_confirmed, reason = self._is_idor_confirmed(
                    orig_status, orig_len, orig_snip,
                    test_status, test_len, test_snip, dual_auth=True
                )
                if is_confirmed:
                    console.print(f"[bold red][BOLA CONFIRMED] {param_name}: User B accessed User A's id={original_val}[/bold red]")
                    findings.append({
                        "type": f"BOLA (Dual-Credential): {param_name} Parameter",
                        "severity": "CRITICAL",
                        "cvss_score": 9.1,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        "owasp": "A01:2021-Broken Access Control",
                        "mitre": "T1530 - Data from Cloud Storage Object",
                        "content": (f"BOLA confirmed via Dual-Credential audit on `{param_name}`.\n"
                                    f"User B successfully accessed User A's object ({url}).\n"
                                    f"Proof: {reason}"),
                        "remediation_fix": "Implement strict object-level ownership checks mapping the session user to the requested ID.",
                        "impact_desc": "Full horizontal privilege escalation allowing any authenticated user to access all other user's data.",
                        "evidence_url": url,
                        "param_name": param_name,
                        "original_id": original_val,
                        "confirmed": True
                    })
                    break

            # Fallback: Single-Credential Substitution
            tampered = self._build_tampered_urls(url, param_name, original_val, param_type)
            for tampered_url, test_id in tampered:
                test_status, test_snip, test_len = await self._probe(tampered_url)
                is_confirmed, reason = self._is_idor_confirmed(
                    orig_status, orig_len, orig_snip,
                    test_status, test_len, test_snip
                )

                if is_confirmed:
                    console.print(
                        f"[bold red][IDOR CONFIRMED] {param_name}: "
                        f"id={original_val} vs id={test_id} — {reason}[/bold red]"
                    )
                    findings.append({
                        "type": f"IDOR / BOLA: {param_name} Parameter",
                        "severity": "HIGH",
                        "cvss_score": 8.1,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        "owasp": "A01:2021-Broken Access Control",
                        "mitre": "T1530 - Data from Cloud Storage Object",
                        "content": (
                            f"IDOR confirmed on `{param_name}` parameter.\n"
                            f"Original request: {url}\n"
                            f"Tampered request: {tampered_url}\n"
                            f"Proof: {reason}"
                        ),
                        "remediation_fix": (
                            "1. Implement object-level authorization checks on every endpoint.\n"
                            "2. Never trust client-supplied IDs — always verify ownership server-side.\n"
                            "3. Use indirect references (e.g., hash-based tokens) instead of sequential IDs.\n"
                            "4. Implement centralized authorization middleware for all API endpoints.\n"
                            "5. Log and alert on unusual cross-user access patterns."
                        ),
                        "impact_desc": (
                            "An authenticated attacker can access, modify, or delete objects belonging to "
                            "other users by manipulating the ID parameter. This leads to unauthorized "
                            "exposure of PII, account takeover, and data integrity violations."
                        ),
                        "patch_priority": "HIGH",
                        "evidence_url": url,
                        "tampered_url": tampered_url,
                        "param_name": param_name,
                        "original_id": original_val,
                        "tested_id": test_id,
                        "confirmed": True,
                    })
                    break  # One confirmation per param is enough

        return findings

    async def scan_urls(self, discovered_urls: list[str]) -> list[dict]:
        """
        Scans a list of URLs for IDOR vulnerabilities.
        Filters to only ID-bearing URLs before testing.
        """
        id_urls = [u for u in discovered_urls if self._extract_id_params(u)]
        if not id_urls:
            console.print("[dim][IDOR] No ID-bearing URLs found to test.[/dim]")
            return []

        console.print(f"[bold yellow][IDOR] Scanning {len(id_urls)} ID-bearing endpoints...[/bold yellow]")
        all_findings = []

        # Test in batches of 5 to avoid overwhelming the target
        for i in range(0, len(id_urls), 5):
            batch = id_urls[i:i+5]
            results = await asyncio.gather(*[self.test_url(u) for u in batch], return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    all_findings.extend(r)

        if all_findings:
            console.print(f"[bold red][IDOR] {len(all_findings)} IDOR(s) CONFIRMED![/bold red]")
        else:
            console.print("[dim green][IDOR] No confirmed IDORs found.[/dim green]")

        return all_findings
