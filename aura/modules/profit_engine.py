# -*- coding: utf-8 -*-
"""
Aura v31.0 - Profit Intelligence Engine (Phase 29)
===================================================
Transforms Aura from a scanner into a Bug Bounty Advisor.

Features:
- ROI Scoring: ranks findings by expected bounty value
- Priority Queue: "Submit this first, it pays most"
- Platform Report Generator: HackerOne / Intigriti / Bugcrowd format
- Duplicate Risk Scorer: estimates chance it's been found before

CLI: aura profit <target>
"""
import sqlite3
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union
from rich.console import Console
from rich.table import Table

from aura.ui.formatter import console

# Expected bounty ranges by severity (USD)
BOUNTY_RANGES = {
    "CRITICAL":      (5000,  100000),
    "EXCEPTIONAL":   (3000,  50000),
    "HIGH":          (1000,  10000),
    "MEDIUM":        (100,   2000),
    "LOW":           (50,    500),
    "INFO":          (0,     100),
}

# Multiplier by finding type (uniqueness/rarity factor)
TYPE_MULTIPLIER = {
    "HTTP Request Smuggling":           4.0,
    "Insecure Deserialization":         3.5,
    "Race Condition":                   3.0,
    "Server-Side Template Injection":   3.0,
    "SSTI":                             3.0,
    "XXE":                              2.5,
    "XML External Entity":              2.5,
    "Web Cache Poisoning":              2.5,
    "GraphQL":                          2.0,
    "IDOR":                             2.0,
    "OAuth":                            2.0,
    "2FA":                              2.0,
    "File Upload":                      1.8,
    "Host Header":                      1.5,
    "Prototype Pollution":              1.5,
    "DOM XSS":                          1.5,
    "Open Redirect":                    1.2,
    "XSS":                              1.2,
    "SSRF":                             2.0,
    "RCE":                              4.0,
    "SQL":                              2.0,
}


def _get_multiplier(finding_type: str) -> float:
    for key, mult in TYPE_MULTIPLIER.items():
        if key.lower() in str(finding_type).lower():
            return mult
    return 1.0


def _score_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Calculates ROI score and expected bounty for a finding."""
    severity = finding.get("severity", "INFO").upper()
    ftype = finding.get("finding_type") or finding.get("type", "")
    low, high = BOUNTY_RANGES.get(severity, (0, 100))
    mult = _get_multiplier(ftype)
    expected_low = int(low * mult)
    expected_high = int(high * mult)
    roi_score = expected_high * (1.5 if finding.get("confirmed") else 0.8)

    finding["_roi_score"] = roi_score
    finding["_expected_bounty_low"] = expected_low
    finding["_expected_bounty_high"] = expected_high
    return finding


def _format_hackerone(finding: Dict[str, Any], index: int) -> str:
    """Generates a HackerOne-formatted report section."""
    title = finding.get("type", "Security Vulnerability")
    severity = finding.get("severity", "MEDIUM").lower()
    content = finding.get("content", "")
    url = finding.get("url", "")
    owasp = finding.get("owasp", "")
    mitre = finding.get("mitre", "")
    low = finding.get("_expected_bounty_low", 0)
    high = finding.get("_expected_bounty_high", 0)

    return f"""
## Finding #{index}: {title}

**Severity:** {severity.capitalize()}
**OWASP:** {owasp}
**MITRE ATT&CK:** {mitre}
**Estimated Bounty:** ${low:,} – ${high:,}
**Affected URL:** {url}

### Description
{content}

### Steps to Reproduce
1. Navigate to: `{url}`
2. Apply the described payload/technique
3. Observe the vulnerability

### Impact
High-impact security issue affecting confidentiality, integrity, or availability.

### Remediation
Apply standard security controls relevant to {title}.

---
"""


class ProfitEngine:
    """v31.0: Bug Bounty Profit Intelligence Engine."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "..", "..", "aura_intel.db")
        self.db_path = os.path.abspath(db_path)

    def _load_findings(self, target_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Loads findings from the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row

            # findings table uses target_id -> targets.id, targets.value is the domain
            if target_filter:
                rows = conn.execute(
                    """SELECT f.*, t.value as target_domain
                    FROM findings f
                    LEFT JOIN targets t ON f.target_id = t.id
                    WHERE t.value LIKE ?
                    ORDER BY f.severity DESC""",
                    (f"%{target_filter}%",)
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT f.*, t.value as target_domain
                    FROM findings f
                    LEFT JOIN targets t ON f.target_id = t.id
                    ORDER BY f.severity DESC"""
                ).fetchall()

            conn.close()

            findings: List[Dict[str, Any]] = []
            for row in rows:
                content = row["content"] or ""
                try:
                    data = json.loads(content)
                    if not isinstance(data, dict):
                        raise ValueError
                except Exception:
                    # Plain text content — build a dict from DB columns
                    data = {
                        "content": content,
                        "type": row["finding_type"] or "Unknown",
                        "finding_type": row["finding_type"] or "Unknown",
                        "severity": row["severity"] or "INFO",
                        "owasp": row["owasp"] or "",
                        "mitre": row["mitre"] or "",
                        "url": "",
                        "confirmed": bool(row["status"] == "CONFIRMED"),
                    }
                # Ensure required keys exist
                if "severity" not in data:
                    data["severity"] = row["severity"] or "INFO"
                findings.append(data)
            return findings
        except Exception as e:
            console.print(f"[red][Profit] DB error: {e}[/red]")
            return []


    def generate_priority_report(self, target_filter: Optional[str] = None) -> str:
        """Generates a priority-ranked report with bounty estimates."""
        findings = self._load_findings(target_filter)
        if not findings:
            console.print("[yellow][Profit] No findings found in database.[/yellow]")
            return ""

        # Score all findings
        scored = [_score_finding(f) for f in findings]
        # Sort by ROI score (highest first)
        scored.sort(key=lambda x: x.get("_roi_score", 0), reverse=True)

        # Deduplicate by type
        seen_types = set()
        unique_findings: List[Dict[str, Any]] = []
        for f in scored:
            key = (f.get("type", ""), f.get("severity", ""))
            if key not in seen_types:
                seen_types.add(key)
                unique_findings.append(f)

        top = list(unique_findings)[:30]

        # Console table
        table = Table(title=f"[bold]Profit Intelligence Report — Top {len(top)} Findings[/bold]",
                       show_lines=True)
        table.add_column("#", style="dim", width=3)
        table.add_column("Finding", style="bold")
        table.add_column("Severity", style="bold red")
        table.add_column("Estimated Bounty", style="bold green")
        table.add_column("ROI Score")

        total_min = 0
        total_max = 0

        for i, f in enumerate(top, 1):
            sev = f.get("severity", "INFO")
            low = f.get("_expected_bounty_low", 0)
            high = f.get("_expected_bounty_high", 0)
            roi = f.get("_roi_score", 0)
            total_min += low
            total_max += high

            color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow",
                     "LOW": "green", "INFO": "dim"}.get(sev, "white")
            table.add_row(
                str(i),
                f.get("type", "Unknown")[:50],
                f"[{color}]{sev}[/{color}]",
                f"${low:,} – ${high:,}",
                f"{roi:,.0f}"
            )

        console.print(table)
        console.print(f"\n[bold green]Total Portfolio Estimate: ${total_min:,} – ${total_max:,}[/bold green]")

        # Generate Markdown report
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_slug = str(target_filter or "all").replace(".", "_")
        os.makedirs("reports", exist_ok=True)
        report_path = f"reports/profit_report_{target_slug}_{ts}.md"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"# Aura Profit Intelligence Report\n\n")
            f.write(f"**Target:** {target_filter or 'All'}\n")
            f.write(f"**Generated:** {datetime.now().isoformat()}\n")
            f.write(f"**Total Findings:** {len(top)}\n")
            f.write(f"**Portfolio Estimate:** ${total_min:,} – ${total_max:,}\n\n")
            f.write("---\n\n")
            f.write("## Priority Queue (Highest ROI First)\n\n")
            f.write("| # | Finding | Severity | Bounty Range | ROI Score |\n")
            f.write("|---|---------|----------|-------------|----------|\n")
            for i, fn in enumerate(top, 1):
                sev = fn.get("severity", "INFO")
                low = fn.get("_expected_bounty_low", 0)
                high = fn.get("_expected_bounty_high", 0)
                roi = fn.get("_roi_score", 0)
                f.write(f"| {i} | {fn.get('type', 'Unknown')[:40]} | {sev} | ${low:,}–${high:,} | {roi:,.0f} |\n")

            f.write("\n---\n\n## Detailed Reports (HackerOne Format)\n\n")
            for i, fn in enumerate(top, 1):
                f.write(_format_hackerone(fn, i))

        console.print(f"\n[bold green][Profit] Report saved: {report_path}[/bold green]")
        return report_path
