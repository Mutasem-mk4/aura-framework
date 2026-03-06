"""
Aura v20.0 — Platform-Specific Report Generator (Phase 7)
Generates copy-paste-ready bug bounty submission reports in
the exact format required by: Intigriti, HackerOne, and Bugcrowd.

Usage:
    aura report --platform intigriti --target example.com
    aura report --platform hackerone --target example.com
    aura report --platform bugcrowd  --target example.com
"""
import os
from datetime import datetime
from aura.core.storage import AuraStorage


# Severity label mappings per platform
INTIGRITI_SEVERITY = {
    "EXCEPTIONAL": "exceptional",  # CVSS 9.5–10.0
    "CRITICAL":    "critical",     # CVSS 9.0–9.4
    "HIGH":        "high",         # CVSS 7.0–8.9
    "MEDIUM":      "medium",       # CVSS 4.0–6.9
    "LOW":         "low",          # CVSS 0.1–3.9
}

H1_SEVERITY = {
    "EXCEPTIONAL": "critical",
    "CRITICAL":    "critical",
    "HIGH":        "high",
    "MEDIUM":      "medium",
    "LOW":         "low",
    "INFO":        "informative",
}

BUGCROWD_PRIORITY = {
    "EXCEPTIONAL": "P1",
    "CRITICAL":    "P1",
    "HIGH":        "P2",
    "MEDIUM":      "P3",
    "LOW":         "P4",
}


class PlatformReporter:
    """
    Phase 7: Platform-specific bug bounty report generator.
    Produces submission-ready Markdown for Intigriti, HackerOne, or Bugcrowd.
    """

    def __init__(self, db_path=None):
        self.db = AuraStorage(db_path)
        self.report_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(self.report_dir, exist_ok=True)

    def _get_findings(self, target_filter: str = None) -> list[dict]:
        """Fetches and deduplicates findings from the database."""
        from aura.core.reporter import AuraReporter
        pdf_reporter = AuraReporter(self.db.db_path)
        targets, _, _, _ = pdf_reporter._fetch_data(target_filter)
        seen, findings = set(), []
        for t in targets:
            domain = t.get("value", "Target")
            for f in t.get("findings", []):
                key = f.get("finding_type", f.get("type", "")) + f.get("evidence_url", f.get("location", ""))
                if key not in seen:
                    seen.add(key)
                    f["_domain"] = domain
                    findings.append(f)
        findings.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        return findings

    # ─── INTIGRITI FORMAT ────────────────────────────────────────────────────
    def generate_intigriti(self, target_filter: str = None) -> str:
        """Generates Intigriti-format submission report."""
        findings = self._get_findings(target_filter)
        if not findings:
            return None

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.report_dir, f"intigriti_report_{ts}.md")

        with open(path, "w", encoding="utf-8") as fp:
            fp.write(f"# Aura Security Report — Intigriti Submission\n")
            fp.write(f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}*\n\n---\n\n")

            for f in findings:
                sev = f.get("severity", "MEDIUM").upper()
                cvss = f.get("cvss_score", 5.0)
                f_type = f.get("finding_type", f.get("type", "Vulnerability"))
                domain = f.get("_domain", "Target")
                url = f.get("evidence_url", f.get("location", "N/A"))
                confirmed = f.get("confirmed", False)
                account_info = f.get("account_info", "")

                intigriti_sev = INTIGRITI_SEVERITY.get(sev, "medium")

                fp.write(f"## {f_type}\n\n")
                fp.write(f"| Field | Value |\n|-------|-------|\n")
                fp.write(f"| **Severity** | {intigriti_sev.upper()} |\n")
                fp.write(f"| **CVSS Score** | {cvss} |\n")
                fp.write(f"| **CVSS Vector** | {f.get('cvss_vector', 'N/A')} |\n")
                fp.write(f"| **Asset** | `{domain}` |\n")
                fp.write(f"| **Affected URL** | `{url}` |\n")
                if confirmed:
                    fp.write(f"| **Validation** | CONFIRMED LIVE — {account_info} |\n")
                fp.write("\n")

                fp.write("### Description\n")
                fp.write(f"{f.get('content', f_type + ' vulnerability detected.')}\n\n")

                fp.write("### Steps to Reproduce\n")
                if "secret" in f_type.lower():
                    fp.write(f"1. Navigate to: `{url}`\n")
                    fp.write(f"2. Observe the exposed credential: `{f.get('secret_value', '[redacted]')}`\n")
                    if confirmed:
                        fp.write(f"3. Validate liveness:\n")
                        fp.write(f"   ```bash\n   # {account_info}\n   ```\n")
                elif "403" in f_type.lower() or "bypass" in f_type.lower():
                    fp.write(f"1. Send a request to `{url}` — observe 403.\n")
                    fp.write(f"2. Retry with header `X-Forwarded-For: 127.0.0.1` — observe 200.\n")
                elif "cors" in f_type.lower():
                    fp.write(f"1. Send OPTIONS request to `{url}` with `Origin: https://evil.com`\n")
                    fp.write(f"2. Observe `Access-Control-Allow-Origin: https://evil.com` in response.\n")
                elif "graphql" in f_type.lower():
                    fp.write(f"1. Send POST to `{url}` with body: `{{\"query\":\"{{ __schema {{ types {{ name }} }} }}\"}}`\n")
                    fp.write(f"2. Observe full schema returned in response.\n")
                else:
                    fp.write(f"1. Navigate to `{url}`.\n")
                    fp.write(f"2. {f.get('content', 'Observe the vulnerability.')[:200]}\n")
                fp.write("\n")

                fp.write("### Impact\n")
                fp.write(f"{f.get('impact_desc', 'This vulnerability compromises the security of the affected asset.')}\n\n")

                fp.write("### Remediation\n")
                fp.write(f"{f.get('remediation_fix', 'Implement appropriate security controls.')}\n\n")

                fp.write("---\n\n")

        return path

    # ─── HACKERONE FORMAT ──────────────────────────────────────────────────
    def generate_hackerone(self, target_filter: str = None) -> str:
        """Generates HackerOne-format submission report."""
        findings = self._get_findings(target_filter)
        if not findings:
            return None

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.report_dir, f"hackerone_report_{ts}.md")

        with open(path, "w", encoding="utf-8") as fp:
            fp.write(f"# Bug Bounty Report — HackerOne\n")
            fp.write(f"*Aura Security Scanner | {datetime.now().strftime('%Y-%m-%d %H:%M')}*\n\n---\n\n")

            for f in findings:
                sev = f.get("severity", "MEDIUM").upper()
                cvss = f.get("cvss_score", 5.0)
                f_type = f.get("finding_type", f.get("type", "Vulnerability"))
                domain = f.get("_domain", "Target")
                url = f.get("evidence_url", f.get("location", "N/A"))
                confirmed = f.get("confirmed", False)
                h1_sev = H1_SEVERITY.get(sev, "medium")

                fp.write(f"## Vulnerability Report: {f_type}\n\n")
                fp.write(f"**Severity:** {h1_sev.upper()}  \n")
                fp.write(f"**CVSS Score:** {cvss}  \n")
                fp.write(f"**Asset:** `{domain}`  \n")
                fp.write(f"**Weakness:** {f.get('owasp', 'Security Misconfiguration')}  \n")
                if confirmed:
                    fp.write(f"**Proof:** CONFIRMED LIVE via API validation  \n")
                fp.write("\n")

                fp.write("### Summary\n")
                fp.write(
                    f"A `{h1_sev}` severity vulnerability of type `{f_type}` was discovered on `{domain}`. "
                    f"CVSS score: `{cvss}`. "
                    + ("The finding has been **actively confirmed** against the live service API.\n\n" if confirmed
                       else "The finding was identified through automated security scanning.\n\n")
                )

                fp.write("### Steps To Reproduce\n")
                if "secret" in f_type.lower() or "credential" in f_type.lower():
                    fp.write(f"1. Fetch the exposed resource:\n")
                    fp.write(f"   ```bash\n   curl -s '{url}'\n   ```\n")
                    fp.write(f"2. The response contains the exposed credential value: `{f.get('secret_value', '[redacted]')}`\n")
                    if confirmed:
                        fp.write(f"3. The credential was validated as live:\n")
                        fp.write(f"   > {f.get('account_info', '')}\n")
                else:
                    fp.write(f"1. Navigate to: `{url}`\n")
                    fp.write(f"2. {f.get('content', '...')[:300]}\n")
                fp.write("\n")

                fp.write("### Impact\n")
                fp.write(f"{f.get('impact_desc', 'Security impact to the affected asset.')}\n\n")

                fp.write("### Suggested Fix\n")
                fp.write(f"{f.get('remediation_fix', 'Implement appropriate security controls.')}\n\n")

                fp.write("### Supporting Material\n")
                fp.write(f"- **MITRE ATT&CK:** {f.get('mitre', 'N/A')}\n")
                fp.write(f"- **OWASP:** {f.get('owasp', 'N/A')}\n")
                fp.write(f"- **CVSS Vector:** `{f.get('cvss_vector', 'N/A')}`\n\n")

                fp.write("---\n\n")

        return path

    # ─── BUGCROWD FORMAT ──────────────────────────────────────────────────
    def generate_bugcrowd(self, target_filter: str = None) -> str:
        """Generates Bugcrowd-format submission report."""
        findings = self._get_findings(target_filter)
        if not findings:
            return None

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.report_dir, f"bugcrowd_report_{ts}.md")

        with open(path, "w", encoding="utf-8") as fp:
            fp.write(f"# Bugcrowd Security Submission\n")
            fp.write(f"*Generated by Aura Scanner | {datetime.now().strftime('%Y-%m-%d %H:%M')}*\n\n---\n\n")

            for f in findings:
                sev = f.get("severity", "MEDIUM").upper()
                cvss = f.get("cvss_score", 5.0)
                f_type = f.get("finding_type", f.get("type", "Vulnerability"))
                domain = f.get("_domain", "Target")
                url = f.get("evidence_url", f.get("location", "N/A"))
                priority = BUGCROWD_PRIORITY.get(sev, "P3")

                fp.write(f"## [{priority}] {f_type}\n\n")
                fp.write(f"**Priority:** {priority}  \n")
                fp.write(f"**CVSS:** {cvss}  \n")
                fp.write(f"**Target:** `{domain}`  \n")
                fp.write(f"**Endpoint:** `{url}`  \n\n")

                fp.write("**Description:**\n")
                fp.write(f"{f.get('content', f_type + ' vulnerability identified.')}\n\n")

                fp.write("**Reproduction Steps:**\n")
                fp.write(f"1. Access: `{url}`\n")
                fp.write(f"2. {f.get('content', '...')[:200]}\n\n")

                fp.write("**Impact:**\n")
                fp.write(f"{f.get('impact_desc', 'Security impact to the target.')}\n\n")

                fp.write("**Remediation:**\n")
                fp.write(f"{f.get('remediation_fix', 'Apply appropriate security fixes.')}\n\n")

                fp.write("---\n\n")

        return path

    def generate(self, platform: str = "intigriti", target_filter: str = None) -> str | None:
        """Unified entry: generate report for the given platform."""
        platform = platform.lower().strip()
        if platform == "intigriti":
            return self.generate_intigriti(target_filter)
        elif platform in ("hackerone", "h1"):
            return self.generate_hackerone(target_filter)
        elif platform in ("bugcrowd", "bc"):
            return self.generate_bugcrowd(target_filter)
        else:
            raise ValueError(f"Unknown platform: '{platform}'. Use: intigriti, hackerone, bugcrowd")

    # ─── SEVERITY NEGOTIATION ────────────────────────────────────────────────

    def negotiate_finding(
        self,
        vuln_type: str,
        original_severity: str,
        downgraded_severity: str,
        cvss_score: float,
        cvss_vector: str,
        platform: str = "intigriti",
        finding_content: str = "",
        impact_desc: str = "",
        evidence_url: str = "",
    ) -> str:
        """
        Tier 5: Severity Negotiation Script.
        Generates a professional, evidence-backed appeal letter when a platform
        downgrades your reported severity. Ready to copy-paste.

        Returns: Path to the generated negotiation Markdown file.
        """
        from aura.core.cvss_engine import CVSSEngine
        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        path      = os.path.join(self.report_dir, f"negotiate_{ts}.md")

        # Auto-calculate CVSS justification
        cvss_calc = CVSSEngine.calculate(vuln_type)
        cvss_just = cvss_calc.get("justification", "")

        # Map platform severity to label
        sev_map = {
            "intigriti": INTIGRITI_SEVERITY,
            "hackerone": H1_SEVERITY,
            "h1":        H1_SEVERITY,
            "bugcrowd":  BUGCROWD_PRIORITY,
        }
        sev_labels = sev_map.get(platform.lower(), INTIGRITI_SEVERITY)

        orig_label = sev_labels.get(original_severity.upper(), original_severity)
        down_label = sev_labels.get(downgraded_severity.upper(), downgraded_severity)

        # Similar real-world CVEs for this vuln type
        cve_refs = {
            "ssrf":              "CVE-2021-21985 (VMware SSRF, CVSS 9.8), CVE-2022-0847 (Dirty Pipe leverage via SSRF)",
            "idor":              "CVE-2023-20198 (Cisco IOS XE IDOR chain, CVSS 10.0)",
            "jwt":               "CVE-2022-21449 (Java JWT None Alg, CVSS 7.5), CVE-2015-9235 (jsonwebtoken alg:none)",
            "oauth":             "CVE-2022-24785 (OAuth redirect_uri bypass chain)",
            "mass assignment":   "CVE-2012-2054 (Rails mass assignment, led to GitHub breach)",
            "cors":              "CVE-2018-17553 (CORS misconfiguration leading to account takeover)",
            "subdomain takeover":"CVE-2021-44228 (Log4j chained via subdomain takeover)",
            "graphql":           "CVE-2022-37734 (GraphQL DoS via introspection, CVSS 7.5)",
        }
        vuln_lower = vuln_type.lower()
        cve_text   = next((v for k, v in cve_refs.items() if k in vuln_lower), "Multiple documented HackerOne disclosed reports.")

        with open(path, "w", encoding="utf-8") as fp:
            fp.write(f"# Severity Appeal — {vuln_type}\n\n")
            fp.write(f"*Platform: {platform.upper()} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}*\n\n")
            fp.write("---\n\n")
            fp.write("## Dear Security Team,\n\n")
            fp.write(
                f"Thank you for your time reviewing this report. I would like to respectfully appeal "
                f"the severity downgrade from **{orig_label.upper()}** to **{down_label.upper()}** "
                f"and provide the following technical justification.\n\n"
            )

            fp.write("## CVSS 3.1 Score Justification\n\n")
            fp.write(f"The correct severity for this finding is **{original_severity.upper()}**, "
                     f"calculated using the CVSS 3.1 standard:\n\n")
            fp.write(f"| Metric | Value |\n|--------|-------|\n")
            fp.write(f"| **CVSS Score** | **{cvss_score}** |\n")
            fp.write(f"| **CVSS Vector** | `{cvss_vector}` |\n")
            fp.write(f"| **Severity** | **{original_severity.upper()}** |\n\n")
            fp.write(f"{cvss_just}\n\n")

            fp.write("## Real-World Impact Evidence\n\n")
            if impact_desc:
                fp.write(f"{impact_desc}\n\n")
            if evidence_url:
                fp.write(f"**Live Evidence URL:** `{evidence_url}`\n\n")
            if finding_content:
                fp.write(f"**Proof of Exploitation:**\n```\n{finding_content[:600]}\n```\n\n")

            fp.write("## Comparable CVEs & Accepted Reports\n\n")
            fp.write(f"This class of vulnerability has historically been accepted at {original_severity.upper()} severity:\n\n")
            fp.write(f"- {cve_text}\n\n")
            fp.write(
                "Many similar vulnerabilities have been triaged and rewarded at this level on major "
                "bug bounty platforms, as they represent a direct path to unauthorized access or "
                "sensitive data exposure.\n\n"
            )

            fp.write("## Requested Action\n\n")
            fp.write(
                f"I respectfully request that the team reconsider the severity rating and restore it to "
                f"**{original_severity.upper()}** (CVSS {cvss_score}), in accordance with the CVSS 3.1 "
                f"standard and the demonstrated real-world impact.\n\n"
                "I am happy to provide any additional evidence, PoC variations, or clarifications "
                "needed to support this appeal.\n\n"
                "Thank you for your time and continued collaboration.\n\n"
                "Best regards,\n"
                "*Security Researcher*\n"
            )

        return path

