"""
markdown_reporter.py — v1.0
Native HackerOne/Bugcrowd Bug Bounty Report Generator.
Converts Aura findings into copy-pasteable Markdown templates.
"""
import os
from datetime import datetime
from collections import defaultdict
from aura.core.reporter import get_mitre

class MarkdownReporter:
    def __init__(self, db_path=None):
        from aura.core.storage import AuraStorage
        self.db = AuraStorage(db_path)
        self.report_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(self.report_dir, exist_ok=True)

    def _get_dynamic_impact(self, f_type: str, domain: str) -> str:
        """Upgrade 3: Targeted Business Impact Engine."""
        f_lower = f_type.lower()
        d_lower = domain.lower()
        
        # 1. Target Context Impact
        target_context = ""
        if "api." in d_lower or "developer." in d_lower:
            target_context = "As this vulnerability is located on a core API endpoint, it presents a severe risk of mass data exfiltration, unauthorized programmatic access, and API key rotation bypass."
        elif "admin." in d_lower or "dashboard." in d_lower or "portal." in d_lower:
            target_context = "As this affects an administrative or internal dashboard, successful exploitation could lead to complete infrastructure compromise, unauthorized privilege escalation, and full access to backend customer data."
        elif "pay" in d_lower or "billing" in d_lower:
            target_context = "As this exists on a payment-related asset, this introduces direct financial liability, potential PCI-DSS compliance failure, and risk of fraudulent transactions."
        
        # 2. Vulnerability Specific Impact
        vuln_impact = ""
        if "secret" in f_lower or "credential" in f_lower:
            vuln_impact = "Exposure of these credentials allows an attacker to impersonate the target application, directly access associated cloud resources (e.g., AWS, Stripe), incurring uncontrolled financial charges, and potentially stealing personally identifiable information (PII) from the database."
        elif "sql" in f_lower or "injection" in f_lower:
            vuln_impact = "SQL Injection permits an attacker to read, modify, or delete all records within the backend database. This includes password hashes, internal application logic, and confidential user data."
        elif "xss" in f_lower or "cross-site" in f_lower:
            vuln_impact = "Cross-Site Scripting allows an attacker to execute arbitrary JavaScript within the context of a victim's browser. This leads to session hijacking (stealing cookies/tokens), unauthorized actions on behalf of the victim, and phishing attacks."
        elif "ssrf" in f_lower:
            vuln_impact = "Server-Side Request Forgery allows an attacker to bypass firewalls and force the server to issue requests to internal, protected resources (e.g., cloud metadata endpoints like 169.254.169.254), leading to unauthorized internal access and server takeover."
        elif "lfi" in f_lower or "file inclusion" in f_lower:
            vuln_impact = "Local File Inclusion allows reading sensitive local files on the server (like /etc/passwd or configuration files containing database passwords), potentially escalating to Remote Code Execution (RCE)."
        else:
            vuln_impact = f"This {f_type} vulnerability allows an attacker to compromise the integrity and confidentiality of the affected asset, leading to unauthorized actions."

        return f"{target_context}\n\n{vuln_impact}".strip()

    def generate_report(self, output_path=None, target_filter=None):
        """Generates a .md file containing all findings formatted for HackerOne."""
        # 1. Fetch Findings (Reusing Reporter Logic)
        from aura.core.reporter import AuraReporter
        pdf_reporter = AuraReporter(self.db.db_path)
        targets, _, _, _ = pdf_reporter._fetch_data(target_filter)

        if not targets:
            return None

        # Gather unique findings
        seen_f = set()
        all_unique = []
        for t in targets:
            domain = t.get("value", "Target")
            for f in t.get('findings', []):
                key = f.get('finding_type', f.get('type', 'Unknown'))
                if key not in seen_f:
                    seen_f.add(key)
                    # inject domain for impact engine
                    f['_target_domain'] = domain
                    all_unique.append(f)
                    
        if not all_unique:
            return None

        # Sort by severity
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        all_unique.sort(key=lambda x: sev_rank.get(x.get('severity', 'INFO'), 0), reverse=True)

        if not output_path:
            output_path = os.path.join(self.report_dir, f"hackerone_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"# Aura Security Assessment - Bug Bounty Report\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")

            for finding in all_unique:
                sev = finding.get('severity', 'INFO')
                f_type = finding.get('finding_type', finding.get('type', 'Unknown'))
                domain = finding.get('_target_domain', 'Target')
                url = finding.get('evidence_url', finding.get('location', ''))
                # HackerOne Title
                cvss = finding.get('cvss_score', 0.0)
                f.write(f"## [{sev} - {cvss}] {f_type} on {domain}\n\n")
                
                # Summary
                f.write("### Summary\n")
                f.write(f"A `{sev}` severity `{f_type}` vulnerability was discovered on the target asset ` {domain} ` with a CVSS score of `{cvss}`.\n\n")
                # Steps To Reproduce
                f.write("### Steps To Reproduce\n")
                # Attempt to extract secret-specific details
                if "secret" in f_type.lower():
                    val_status = finding.get('validation_status', 'UNVERIFIED')
                    val_evidence = finding.get('validation_evidence', '')
                    secret_val = finding.get('secret_value', '********')
                    
                    if "VALID" in val_status:
                        f.write(f"**Verification Status:** ✅ CONFIRMED EXPLOITABLE\n\n")
                    f.write("1. Navigate to the following exposed endpoint:\n")
                    f.write(f"   ```http\n   GET {url}\n   ```\n")
                    f.write(f"2. Observe the leaked `{f_type}` credential (partial value: `{secret_val}`).\n")
                    f.write("3. You can reproduce this immediately via terminal:\n")
                    f.write(f"   ```bash\n   curl -sk \"{url}\" | grep -oE \"[A-Za-z0-9/+=]{{32,64}}\"\n   ```\n")
                    
                    if val_evidence:
                        f.write("4. Direct API authentication confirms the credential is live and holds access privileges:\n")
                        f.write(f"   ```json\n   {val_evidence}\n   ```\n")
                else:
                    payload = finding.get('payload', 'Target-specific payload')
                    f.write("1. Navigate to the vulnerable endpoint:\n")
                    f.write(f"   `{url}`\n")
                    f.write(f"2. Inject the following payload:\n")
                    f.write(f"   ```\n   {payload}\n   ```\n")
                    f.write("3. Observe the successful execution/bypass.\n")
                
                f.write("\n")
                
                # Impact Breakdown (Dynamic Engine)
                f.write("### Business Impact\n")
                impact_text = self._get_dynamic_impact(f_type, domain)
                f.write(f"{impact_text}\n\n")
                
                # Remediation
                f.write("### Remediation\n")
                f.write(f"{finding.get('remediation_fix', 'Implement appropriate input validation and access controls.')}\n\n")
                
                f.write("---\n\n")
                
        return output_path
