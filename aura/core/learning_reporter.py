"""
Aura v22.X — Learning Reporter
Plain-English vulnerability explanations for beginners.

Usage:
    from aura.core.learning_reporter import LearningReporter
    LearningReporter.print_learning_summary(findings)
    LearningReporter.generate_learning_report(finding)
"""
import os
from datetime import datetime
from typing import Optional, List, Dict
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


class LearningReporter:
    """
    Enhanced reporter with beginner-friendly explanations.
    Extends the capabilities of MarkdownReporter for educational purposes.
    """

    # Severity explanations in plain English
    SEVERITY_EXPLANATIONS = {
        "CRITICAL": {
            "plain": "This is extremely serious. An attacker can completely take over the system, steal all data, or cause major damage without any user interaction.",
            "action": "Submit immediately. These are top priority and rewarded quickly.",
            "bounty_range": "$2,000 - $10,000+"
        },
        "HIGH": {
            "plain": "This is very serious. An attacker can gain significant access or steal sensitive data with minimal effort.",
            "action": "Submit soon. These are high priority for most programs.",
            "bounty_range": "$1,000 - $5,000"
        },
        "MEDIUM": {
            "plain": "This is moderately serious. An attacker needs some conditions to be met or user interaction to exploit.",
            "action": "Submit when convenient. Document well with clear reproduction steps.",
            "bounty_range": "$200 - $1,000"
        },
        "LOW": {
            "plain": "This is a minor issue. It may be hard to exploit or the impact is limited.",
            "action": "Submit if it doesn't duplicate existing reports. Focus on clear documentation.",
            "bounty_range": "$50 - $200"
        },
        "INFO": {
            "plain": "This is informational. Not a vulnerability but useful intelligence that could help in other attacks.",
            "action": "Optional to submit. Some programs accept informational findings.",
            "bounty_range": "$0 - $50"
        }
    }

    # CVSS score explanations
    CVSS_EXPLANATIONS = {
        (9.0, 10.0): "Critical - Complete system compromise possible, no user interaction needed",
        (7.0, 8.9): "High - Significant impact, urgent attention needed",
        (4.0, 6.9): "Medium - Moderate impact, should be fixed",
        (0.1, 3.9): "Low - Minimal impact, hard to exploit",
        (0.0, 0.0): "Informational - No immediate security impact"
    }

    # Remediation steps per vulnerability type
    REMEDIATION_STEPS = {
        "xss": [
            "1. Sanitize all user input - remove HTML tags and script tags",
            "2. Use output encoding when displaying user data (HTML entities)",
            "3. Implement Content Security Policy (CSP) headers",
            "4. Use secure frameworks that auto-escape by default"
        ],
        "sql injection": [
            "1. Use parameterized queries (prepared statements)",
            "2. Never concatenate user input into SQL queries",
            "3. Use ORM frameworks that handle escaping automatically",
            "4. Apply least privilege to database accounts"
        ],
        "ssrf": [
            "1. Block internal IP ranges from being accessed",
            "2. Validate and sanitize all URL inputs",
            "3. Disable unnecessary URL schemas (file://, dict://, etc.)",
            "4. Use allowlists for permitted destinations"
        ],
        "idor": [
            "1. Implement proper authorization checks on all object access",
            "2. Use indirect references instead of direct object IDs",
            "3. Validate user owns the resource before access",
            "4. Use framework-level access controls"
        ],
        "open redirect": [
            "1. Use relative URLs instead of absolute when possible",
            "2. Implement URL validation with allowlists",
            "3. Never include user input directly in redirect URLs",
            "4. Use a warning page for external redirects"
        ],
        "subdomain takeover": [
            "1. Claim unused DNS records or remove them",
            "2. Use CNAME validation tools regularly",
            "3. Monitor for dangling DNS entries",
            "4. Set 404 or default response for unused subdomains"
        ],
        "command injection": [
            "1. Avoid passing user input to system shells",
            "2. Use built-in API functions that don't invoke a shell",
            "3. Implement strict allow-listing for permitted commands",
            "4. Use sandboxing for any necessary command execution"
        ],
        "xxe": [
            "1. Disable XML external entity processing in parsers",
            "2. Use less complex data formats like JSON when possible",
            "3. Validate and sanitize XML input",
            "4. Apply secure XML parser configurations"
        ],
        "lfi": [
            "1. Avoid including files based on user input",
            "2. Use whitelist approach for allowed files",
            "3. Sanitize file paths and prevent path traversal",
            "4. Run applications with minimal filesystem permissions"
        ],
        "rce": [
            "1. Never pass user input to eval(), exec(), or similar functions",
            "2. Use secure coding practices for code execution",
            "3. Implement input validation and sanitization",
            "4. Apply principle of least privilege"
        ],
        "csrf": [
            "1. Implement anti-CSRF tokens for all state-changing operations",
            "2. Use SameSite cookies",
            "3. Check Origin/Referer headers",
            "4. Implement proper authentication checks"
        ],
        "auth bypass": [
            "1. Implement strong authentication mechanisms",
            "2. Use secure password reset flows",
            "3. Add multi-factor authentication",
            "4. Rate limit authentication endpoints"
        ],
        "jwt": [
            "1. Use strong, asymmetric signing algorithms (RS256)",
            "2. Validate all JWT claims (expiration, issuer, etc.)",
            "3. Avoid 'none' algorithm",
            "4. Implement proper token storage on client"
        ]
    }

    # OWASP Top 10 mapping
    OWASP_MAPPING = {
        "xss": "A03:2021 - Injection",
        "sql injection": "A03:2021 - Injection",
        "command injection": "A03:2021 - Injection",
        "xxe": "A03:2021 - Injection",
        "lfi": "A03:2021 - Injection",
        "idor": "A01:2021 - Broken Access Control",
        "auth bypass": "A07:2021 - Identification and Authentication Failures",
        "csrf": "A01:2021 - Broken Access Control",
        "ssrf": "A10:2021 - Server-Side Request Forgery",
        "open redirect": "A01:2021 - Broken Access Control"
    }

    @classmethod
    def _explain_cvss(cls, score: float) -> str:
        """Get plain-English explanation of CVSS score."""
        if score == 0:
            return "Informational - No immediate security impact"
        for (low, high), explanation in cls.CVSS_EXPLANATIONS.items():
            if low <= score <= high:
                return explanation
        return "Unknown severity"

    @classmethod
    def _explain_severity(cls, severity: str) -> dict:
        """Get plain-English explanation of severity level."""
        return cls.SEVERITY_EXPLANATIONS.get(
            severity.upper(),
            {"plain": "Unknown severity", "action": "Review manually", "bounty_range": "Varies"}
        )

    @classmethod
    def _get_remediation_steps(cls, vuln_type: str) -> list:
        """Get remediation steps for a vulnerability type."""
        key = vuln_type.lower().replace(" ", "_").replace("-", "_")

        # Direct match
        if key in cls.REMEDIATION_STEPS:
            return cls.REMEDIATION_STEPS[key]

        # Partial match
        for k, steps in cls.REMEDIATION_STEPS.items():
            if k in key or key in k:
                return steps

        # Generic fallback
        return [
            "1. Investigate this vulnerability type",
            "2. Research secure implementation patterns",
            "3. Test fixes thoroughly before deployment",
            "4. Consider using automated security tools"
        ]

    @classmethod
    def _get_owasp(cls, vuln_type: str) -> str:
        """Get OWASP category for vulnerability type."""
        key = vuln_type.lower().replace(" ", "_").replace("-", "_")

        # Direct match
        if key in cls.OWASP_MAPPING:
            return cls.OWASP_MAPPING[key]

        # Partial match
        for k, owasp in cls.OWASP_MAPPING.items():
            if k in key or key in k:
                return owasp

        return "Unknown - Check OWASP Top 10"

    @classmethod
    def print_learning_summary(cls, findings: List[Dict]) -> None:
        """Print a plain-English summary table for findings."""
        if not findings:
            console.print("[dim]No findings to summarize.[/dim]")
            return

        table = Table(
            title="[bold]📚 Findings Summary — Plain English[/bold]",
            show_header=True,
            header_style="bold magenta"
        )
        table.add_column("Type", style="cyan", no_wrap=False)
        table.add_column("Severity", style="yellow")
        table.add_column("CVSS", style="magenta", justify="center")
        table.add_column("What It Means", style="white")

        for f in findings:
            vuln_type = f.get("finding_type", "Unknown")
            severity = f.get("severity", "INFO")
            cvss = f.get("cvss_score", f.get("cvss", 0.0))
            sev_exp = cls._explain_severity(severity)

            # Truncate explanation if too long
            explanation = sev_exp["plain"]
            if len(explanation) > 60:
                explanation = explanation[:57] + "..."

            table.add_row(
                vuln_type,
                severity,
                f"{cvss:.1f}" if cvss else "N/A",
                explanation
            )

        console.print(table)

    @classmethod
    def print_finding_detail(cls, finding: Dict) -> None:
        """Print detailed information about a single finding."""
        vuln_type = finding.get("finding_type", "Unknown")
        severity = finding.get("severity", "INFO")
        cvss = finding.get("cvss_score", finding.get("cvss", 0.0))
        url = finding.get("url", "N/A")
        parameter = finding.get("parameter", "N/A")
        payload = finding.get("payload", "N/A")

        sev_exp = cls._explain_severity(severity)
        cvss_exp = cls._explain_cvss(cvss)
        steps = cls._get_remediation_steps(vuln_type)
        owasp = cls._get_owasp(vuln_type)

        panel_content = f"""[bold cyan]Vulnerability:[/bold cyan] {vuln_type}
[bold yellow]Severity:[/bold yellow] {severity} — {sev_exp['plain']}
[bold magenta]CVSS Score:[/bold magenta] {cvss} — {cvss_exp}
[bold green]OWASP:[/bold green] {owasp}
[bold]URL:[/bold] {url}
[bold]Parameter:[/bold] {parameter}

[bold yellow]💰 Typical Bounty:[/bold yellow] {sev_exp['bounty_range']}

[bold cyan]What to do:[/bold cyan] {sev_exp['action']}

[bold green]How to fix (for developer):[/bold green]
{chr(10).join(steps)}

[bold]Sample Payload:[/bold]
[code]{payload}[/code]"""

        panel = Panel(
            panel_content,
            title=f"[bold {cls._get_severity_color(severity)}]🔍 {vuln_type} Detail[/bold]",
            border_style=cls._get_severity_color(severity),
            padding=(1, 2)
        )
        console.print(panel)

    @classmethod
    def _get_severity_color(cls, severity: str) -> str:
        """Get Rich color for severity."""
        colors = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "cyan",
            "LOW": "green",
            "INFO": "grey"
        }
        return colors.get(severity.upper(), "white")

    @classmethod
    def generate_learning_report(cls, finding: Dict, output_path: str = None) -> str:
        """Generate a beginner-friendly report for a single finding."""
        vuln_type = finding.get("finding_type", "Unknown")
        severity = finding.get("severity", "INFO")
        cvss = finding.get("cvss_score", finding.get("cvss", 0.0))
        url = finding.get("url", "N/A")
        parameter = finding.get("parameter", "N/A")
        payload = finding.get("payload", "N/A")
        description = finding.get("description", "")

        sev_exp = cls._explain_severity(severity)
        cvss_exp = cls._explain_cvss(cvss)
        steps = cls._get_remediation_steps(vuln_type)
        owasp = cls._get_owasp(vuln_type)

        # Get resources from clinic
        try:
            from aura.modules.clinic import VulnClinic
            resources = VulnClinic.get_tip(vuln_type)
        except Exception:
            resources = {"resources": {"portswigger": "https://portswigger.net"}}

        report = f"""# {vuln_type} - Learning Report

## Quick Summary

**Severity:** {severity} — {sev_exp['plain']}

**CVSS Score:** {cvss} — {cvss_exp}

**OWASP Category:** {owasp}

**What to do:** {sev_exp['action']}

**Typical Bounty Range:** {sev_exp['bounty_range']}

---

## What is {vuln_type}?

{description or sev_exp['plain']}

---

## Why This Matters

{sev_exp['plain']}

A successful exploit could:
- Steal sensitive data (passwords, personal information, payment details)
- Gain unauthorized access to accounts or systems
- Damage the reputation and trust of the affected organization

---

## Technical Details

**Affected URL:** `{url}`

**Vulnerable Parameter:** `{parameter}`

**Sample Payload:**
```
{payload}
```

---

## How to Prove This Vulnerability

1. Identify the vulnerable parameter or endpoint
2. Craft a proof-of-concept (PoC) that demonstrates the issue
3. Document your steps clearly with screenshots or recordings
4. Show the actual impact with sample data (not real user data)

---

## How to Fix It (For the Developer)

{chr(10).join(steps)}

---

## Learn More

- **PortSwigger:** {resources.get('resources', {}).get('portswigger', 'https://portswigger.net')}
- **OWASP:** {resources.get('resources', {}).get('owasp', 'https://owasp.org')}
- **Practice Labs:** {resources.get('resources', {}).get('academy', 'https://portswigger.net/web-security/all-labs')}

---

*Generated by Aura Clinic — Learn as you hunt!*
*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""

        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report)

        return report

    @classmethod
    def print_severity_legend(cls) -> None:
        """Print a legend explaining severity levels."""
        console.print("\n[bold]Severity Legend:[/bold]\n")

        table = Table(show_header=True, header_style="bold white")
        table.add_column("Severity", style="bold")
        table.add_column("What It Means", style="white")
        table.add_column("Typical Bounty", style="green")

        for sev, data in cls.SEVERITY_EXPLANATIONS.items():
            table.add_row(sev, data["plain"][:50] + "..." if len(data["plain"]) > 50 else data["plain"], data["bounty_range"])

        console.print(table)
        console.print()
