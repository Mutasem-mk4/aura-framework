"""
scope_checker.py — v1.0
Checks if a domain is in-scope for known public bug bounty programs.
Queries HackerOne and Bugcrowd public APIs.
"""
import httpx
import re
from typing import List
from aura.core import state

class ScopeChecker:
    """Checks target domain against known public bug bounty program scopes."""

    # Manual Whitelist for verified high-ROI programs (including Phase 9 research)
    VERIFIED_WHITELIST = {
        "ubisoft.com": {"platform": "Intigriti", "url": "https://app.intigriti.com/programs/ubisoft/ubisoftgamesecbbp"},
        "digitalocean.com": {"platform": "Intigriti", "url": "https://app.intigriti.com/programs/digitalocean/digitalocean"},
        "monzo.com": {"platform": "Intigriti", "url": "https://app.intigriti.com/programs/monzobank/monzopublicbugbountyprogram"},
        "aikido.dev": {"platform": "Intigriti", "url": "https://app.intigriti.com/programs/aikido/aikidoruntime/detail"},
        "intel.com": {"platform": "Intigriti", "url": "https://app.intigriti.com/programs/intel/intel"},
        "amd.com": {"platform": "Intigriti", "url": "https://app.intigriti.com/programs/amd/amd-psbbp"},
        "captureourflag.com": {"platform": "Intigriti", "url": "https://app.intigriti.com/programs/captureourflag/captureourflag"},
        "polyglot.ninja": {"platform": "Intigriti", "url": "https://app.intigriti.com/programs/captureourflag/captureourflag"}
    }

    HACKERONE_API = "https://api.hackerone.com/v1/hackers/programs"
    BUGCROWD_API  = "https://bugcrowd.com/programs.json"

    def __init__(self, in_scope_rules: List[str] = None, out_of_scope_rules: List[str] = None):
        self.in_scope = in_scope_rules or []
        self.out_of_scope = out_of_scope_rules or []

    def load_rules(self, in_scope: List[str], out_of_scope: List[str]):
        """Dynamically loads rules for a specific engagement."""
        self.in_scope = in_scope
        self.out_of_scope = out_of_scope

    def _match_pattern(self, target: str, pattern: str) -> bool:
        """Helper to match wildcard patterns like *.example.com"""
        regex_pattern = "^" + re.escape(pattern).replace("\\*", ".*") + "$"
        return bool(re.match(regex_pattern, target))

    def is_in_scope(self, target: str) -> bool:
        """
        v17.0 Zero-Rejection Engine: Strict Scope Guard.
        Validates if the target domain/subdomain is strictly in scope.
        Returns False if it hits an out-of-scope rule.
        """
        from rich.console import Console
        console = Console()
        
        if not target:
            return False
            
        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]

        # 1. Check Out-of-Scope First (Deny list overrides everything)
        for oos_rule in self.out_of_scope:
            if self._match_pattern(clean_target, oos_rule):
                console.print(f"[bold red][SCOPE GUARD] TARGET REJECTED: {clean_target} matches OUT-OF-SCOPE rule ({oos_rule}).[/bold red]")
                return False

        # If no explicit in-scope rules exist, assume it's open
        if not self.in_scope:
            return True

        # 2. Check In-Scope explicitly
        for in_rule in self.in_scope:
            if self._match_pattern(clean_target, in_rule):
                return True

        # 3. Default deny if strict in-scope is defined but no match
        console.print(f"[bold yellow][SCOPE GUARD] TARGET SKIPPED: {clean_target} does not match any IN-SCOPE rules.[/bold yellow]")
        return False

    async def check_scope(self, domain: str) -> dict:
        """
        Checks HackerOne, Bugcrowd, and the internal Verified Whitelist.
        """
        clean_domain = re.sub(r"^https?://", "", domain).split("/")[0].lower()
        base = ".".join(clean_domain.split(".")[-2:])  # e.g. aikido.dev

        # 1. Check Local Whitelist (Fastest)
        if base in self.VERIFIED_WHITELIST:
            prog = self.VERIFIED_WHITELIST[base]
            return {
                "in_scope": True,
                "platform": prog["platform"],
                "program":  base,
                "scope_url": prog["url"],
                "warning":  f"[SUCCESS] '{clean_domain}' is a VERIFIED target on {prog['platform']}.",
            }

        result = {
            "in_scope": None,
            "platform": None,
            "program":  None,
            "scope_url": None,
            "warning":  f"[WARN] Domain '{clean_domain}' not found in any indexed public bug bounty program.",
        }

        try:
            async with httpx.AsyncClient(timeout=state.NETWORK_TIMEOUT, verify=False) as client:
                # ── HackerOne public programs (no auth needed for public list) ──
                h1_resp = await client.get(
                    self.HACKERONE_API,
                    headers={"Accept": "application/json"},
                    params={"page[size]": 100}
                )
                if h1_resp.status_code == 200:
                    programs = h1_resp.json().get("data", [])
                    for prog in programs:
                        attrs = prog.get("attributes", {})
                        handle = attrs.get("handle", "")
                        # Check if domain appears in handle or policy_url
                        policy_url = attrs.get("policy_url", "")
                        if base in handle or base in policy_url:
                            result.update({
                                "in_scope": True,
                                "platform": "HackerOne",
                                "program":  handle,
                                "scope_url": f"https://hackerone.com/{handle}",
                                "warning":  f"[SUCCESS] '{clean_domain}' appears in HackerOne program: {handle}",
                            })
                            return result

                # ── Bugcrowd public programs ──
                bc_resp = await client.get(
                    self.BUGCROWD_API,
                    headers={"Accept": "application/json"}
                )
                if bc_resp.status_code == 200:
                    programs = bc_resp.json().get("programs", [])
                    for prog in programs:
                        prog_url = prog.get("program_url", "")
                        name = prog.get("name", "").lower()
                        if base in name or base in prog_url:
                            result.update({
                                "in_scope": True,
                                "platform": "Bugcrowd",
                                "program":  name,
                                "scope_url": f"https://bugcrowd.com{prog_url}",
                                "warning":  f"[SUCCESS] '{clean_domain}' appears in Bugcrowd program: {name}",
                            })
                            return result

        except Exception as e:
            result["warning"] = f"[WARN] Scope check failed: {str(e)[:80]}. Submit with caution."

        return result
