"""
scope_checker.py — v1.0
Checks if a domain is in-scope for known public bug bounty programs.
Queries HackerOne and Bugcrowd public APIs.
"""
import httpx
import re
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
        "amd.com": {"platform": "Intigriti", "url": "https://app.intigriti.com/programs/amd/amd-psbbp"}
    }

    HACKERONE_API = "https://api.hackerone.com/v1/hackers/programs"
    BUGCROWD_API  = "https://bugcrowd.com/programs.json"

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
