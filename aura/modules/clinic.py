"""
Aura v22.X — Clinic: Educational Tips Engine
Provides beginner-friendly explanations for vulnerabilities found.

Usage:
    from aura.modules.clinic import VulnClinic
    VulnClinic.show_phase_tips(findings)
    VulnClinic.render_tip_panel("xss", finding_data)
"""
import json
import os
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# Resources directory - try multiple paths for flexibility
_RESOURCES_DIR = os.path.join(os.path.dirname(__file__), "..", "resources", "vuln_education")


class VulnClinic:
    """
    Educational tips engine for beginner hunters.
    Provides plain-English explanations for vulnerability types.
    """

    # Built-in vulnerability education data (fallback if JSON files not found)
    VULN_DATA = {
        "xss": {
            "name": "Cross-Site Scripting (XSS)",
            "category": "Web Security",
            "description": "XSS allows attackers to inject malicious scripts into web pages viewed by other users.",
            "why_matters": "Attackers can steal session cookies, deface websites, or redirect users to phishing sites.",
            "severity_levels": {
                "reflected": {"cvss_range": "4.0-6.0", "impact": "Medium - requires user interaction"},
                "stored": {"cvss_range": "6.0-8.0", "impact": "High - affects all users"},
                "dom": {"cvss_range": "4.0-7.0", "impact": "Medium - client-side only"}
            },
            "resources": {
                "owasp": "https://owasp.org/www-community/attacks/xss/",
                "portswigger": "https://portswigger.net/web-security/cross-site-scripting",
                "academy": "https://portswigger.net/web-security/all-labs#cross-site-scripting"
            }
        },
        "sql injection": {
            "name": "SQL Injection",
            "category": "Injection",
            "description": "SQL Injection allows attackers to execute arbitrary SQL queries on the database.",
            "why_matters": "Attackers can read, modify, or delete sensitive data in the database.",
            "severity_levels": {
                "standard": {"cvss_range": "9.0-10.0", "impact": "Critical - full database compromise"},
                "blind": {"cvss_range": "6.0-8.0", "impact": "High - requires careful exploitation"}
            },
            "resources": {
                "owasp": "https://owasp.org/www-community/attacks/SQL_Injection",
                "portswigger": "https://portswigger.net/web-security/sql-injection",
                "academy": "https://portswigger.net/web-security/all-labs#sql-injection"
            }
        },
        "ssrf": {
            "name": "Server-Side Request Forgery (SSRF)",
            "category": "Web Security",
            "description": "SSRF lets attackers abuse server to make internal requests to internal services.",
            "why_matters": "Attackers can access internal services like AWS metadata, internal databases, or localhost.",
            "severity_levels": {
                "standard": {"cvss_range": "8.0-10.0", "impact": "Critical - internal network access"},
                "blind": {"cvss_range": "5.0-7.0", "impact": "Medium - limited feedback"}
            },
            "resources": {
                "owasp": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "portswigger": "https://portswigger.net/web-security/ssrf",
                "academy": "https://portswigger.net/web-security/all-labs#server-side-request-forgery"
            }
        },
        "idor": {
            "name": "Insecure Direct Object Reference (IDOR/BOLA)",
            "category": "Access Control",
            "description": "IDOR/BOLA allows accessing other users' resources by manipulating object IDs.",
            "why_matters": "Attackers can view, modify, or delete other users' data without authorization.",
            "severity_levels": {
                "standard": {"cvss_range": "6.0-8.0", "impact": "High - unauthorized data access"}
            },
            "resources": {
                "owasp": "https://owasp.org/www-community/vulnerabilities/Broken_Object_Level_Authorization",
                "portswigger": "https://portswigger.net/web-security/idor",
                "academy": "https://portswigger.net/web-security/all-labs#idor"
            }
        },
        "open redirect": {
            "name": "Open Redirect",
            "category": "Web Security",
            "description": "Open Redirect allows attackers to redirect victims to malicious sites.",
            "why_matters": "Attackers can phishing users by redirecting them to fake login pages.",
            "severity_levels": {
                "standard": {"cvss_range": "3.0-6.0", "impact": "Medium - requires user interaction"}
            },
            "resources": {
                "owasp": "https://owasp.org/www/community/vulnerabilities/Unvalidated_Redirects_and_Forwards",
                "portswigger": "https://portswigger.net/web-security/open-redirect",
                "academy": "https://portswigger.net/web-security/all-labs#open-redirection"
            }
        },
        "subdomain takeover": {
            "name": "Subdomain Takeover",
            "category": "DNS Security",
            "description": "Subdomain Takeover occurs when a subdomain points to unclaimed cloud resources.",
            "why_matters": "Attackers can host malicious content on trusted subdomain, enabling phishing.",
            "severity_levels": {
                "aws": {"cvss_range": "6.0-8.0", "impact": "High - cloud account access"},
                "github": {"cvss_range": "4.0-6.0", "impact": "Medium - reputation damage"}
            },
            "resources": {
                "owasp": "https://owasp.org/www/community/vulnerabilities/Insecure_Direct_Object_Reference",
                "portswigger": "https://portswigger.net/web-security/host-header",
                "academy": "https://portswigger.net/web-security/all-labs"
            }
        },
        "command injection": {
            "name": "OS Command Injection",
            "category": "Injection",
            "description": "Command Injection allows attackers to execute OS commands on the server.",
            "why_matters": "Attackers can gain full control of the server, install malware, or pivot to other systems.",
            "severity_levels": {
                "standard": {"cvss_range": "9.0-10.0", "impact": "Critical - RCE possible"}
            },
            "resources": {
                "owasp": "https://owasp.org/www-community/attacks/Command_Injection",
                "portswigger": "https://portswigger.net/web-security/os-command-injection",
                "academy": "https://portswigger.net/web-security/all-labs#os-command-injection"
            }
        },
        "xxe": {
            "name": "XML External Entity (XXE)",
            "category": "Injection",
            "description": "XXE allows attackers to read internal files or perform SSRF via XML parsing.",
            "why_matters": "Attackers can read sensitive files, probe internal network, or cause DoS.",
            "severity_levels": {
                "standard": {"cvss_range": "6.0-8.0", "impact": "High - file read and SSRF"}
            },
            "resources": {
                "owasp": "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                "portswigger": "https://portswigger.net/web-security/xxe",
                "academy": "https://portswigger.net/web-security/all-labs#xml-external-entity-xxe"
            }
        },
        "lfi": {
            "name": "Local File Inclusion (LFI)",
            "category": "File Inclusion",
            "description": "LFI allows attackers to include local files on the server.",
            "why_matters": "Attackers can read sensitive files like /etc/passwd, source code, or credentials.",
            "severity_levels": {
                "standard": {"cvss_range": "5.0-7.0", "impact": "Medium - file read"},
                "rce": {"cvss_range": "9.0-10.0", "impact": "Critical - via log poisoning or PHP wrappers"}
            },
            "resources": {
                "owasp": "https://owasp.org/www-community/vulnerabilities/Path_Traversal",
                "portswigger": "https://portswigger.net/web-security/file-inclusion",
                "academy": "https://portswigger.net/web-security/all-labs#path-traversal"
            }
        },
        "rce": {
            "name": "Remote Code Execution (RCE)",
            "category": "Code Execution",
            "description": "RCE allows attackers to execute arbitrary code on the target server.",
            "why_matters": "Full server compromise, data theft, malware installation, and lateral movement.",
            "severity_levels": {
                "standard": {"cvss_range": "9.0-10.0", "impact": "Critical - complete system compromise"}
            },
            "resources": {
                "owasp": "https://owasp.org/www-community/vulnerabilities/Injection",
                "portswigger": "https://portswigger.net/web-security/",
                "academy": "https://portswigger.net/web-security/all-labs"
            }
        },
        "csrf": {
            "name": "Cross-Site Request Forgery (CSRF)",
            "category": "Web Security",
            "description": "CSRF forces users to execute unwanted actions on web applications.",
            "why_matters": "Attackers can force users to change passwords, transfer money, or modify data.",
            "severity_levels": {
                "standard": {"cvss_range": "4.0-6.0", "impact": "Medium - user interaction required"}
            },
            "resources": {
                "owasp": "https://owasp.org/www-community/attacks/csrf",
                "portswigger": "https://portswigger.net/web-security/csrf",
                "academy": "https://portswigger.net/web-security/all-labs#cross-site-request-forgery"
            }
        },
        "idor/b": {
            "name": "Broken Object Level Authorization (BOLA/IDOR)",
            "category": "Access Control",
            "description": "BOLA occurs when an application exposes object IDs and doesn't properly validate access.",
            "why_matters": "Users can access resources belonging to other users (accounts, files, orders).",
            "severity_levels": {
                "standard": {"cvss_range": "6.0-8.0", "impact": "High - unauthorized data access"}
            },
            "resources": {
                "owasp": "https://owasp.org/www/API_Security_Risk_Broken_Object_Level_Authorization",
                "portswigger": "https://portswigger.net/web-security/idor",
                "academy": "https://portswigger.net/web-security/all-labs#broken-object-level-authorization"
            }
        },
        "auth bypass": {
            "name": "Authentication Bypass",
            "category": "Access Control",
            "description": "Authentication bypass allows attackers to access accounts without proper credentials.",
            "why_matters": "Full account takeover is possible without knowing the password.",
            "severity_levels": {
                "standard": {"cvss_range": "8.0-10.0", "impact": "Critical - account takeover"}
            },
            "resources": {
                "owasp": "https://owasp.org/www-community/vulnerabilities/Authentication",
                "portswigger": "https://portswigger.net/web-security/all-labs"
            }
        }
    }

    # OWASP/PortSwigger resource links (fallback)
    RESOURCES = {
        "xss": {
            "owasp": "https://owasp.org/www-community/attacks/xss/",
            "portswigger": "https://portswigger.net/web-security/cross-site-scripting"
        },
        "sql injection": {
            "owasp": "https://owasp.org/www-community/attacks/SQL_Injection",
            "portswigger": "https://portswigger.net/web-security/sql-injection"
        },
        "ssrf": {
            "owasp": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "portswigger": "https://portswigger.net/web-security/ssrf"
        },
        "idor": {
            "owasp": "https://owasp.org/www-community/vulnerabilities/Broken_Object_Level_Authorization",
            "portswigger": "https://portswigger.net/web-security/idor"
        },
        "open redirect": {
            "owasp": "https://owasp.org/www-community/vulnerabilities/Unvalidated_Redirects_and_Forwards",
            "portswigger": "https://portswigger.net/web-security/open-redirect"
        },
        "subdomain takeover": {
            "owasp": "https://owasp.org/www/community/vulnerabilities/Insecure_Direct_Object_Reference",
            "portswigger": "https://portswigger.net/web-security/host-header"
        }
    }

    @classmethod
    def get_tip(cls, vuln_type: str) -> dict:
        """
        Returns educational content for a vulnerability type.
        Tries to load from JSON first, falls back to built-in data.
        """
        key = vuln_type.lower().strip()

        # Try to load from JSON file
        json_path = os.path.join(_RESOURCES_DIR, f"{key.replace(' ', '_').replace('-', '_')}.json")
        if os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        # Try fuzzy matching with built-in data
        for k, v in cls.VULN_DATA.items():
            if k in key or key in k:
                return v

        # Try exact match
        if key in cls.VULN_DATA:
            return cls.VULN_DATA[key]

        # Fallback
        return {
            "name": vuln_type,
            "category": "Unknown",
            "description": f"Learn more about {vuln_type} security vulnerabilities.",
            "why_matters": "This vulnerability could lead to security issues if exploited.",
            "resources": {
                "owasp": "https://owasp.org/",
                "portswigger": "https://portswigger.net/"
            }
        }

    @classmethod
    def render_tip_panel(cls, vuln_type: str, finding_data: dict = None) -> Panel:
        """
        Renders a Rich Panel with educational content.
        """
        tip = cls.get_tip(vuln_type)
        severity = finding_data.get("severity", "MEDIUM") if finding_data else "MEDIUM"

        sev_colors = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "cyan",
            "LOW": "green",
            "INFO": "grey"
        }
        color = sev_colors.get(severity.upper(), "white")

        vuln_name = tip.get("name", vuln_type)
        description = tip.get("description", "")
        why_matters = tip.get("why_matters", "This vulnerability could lead to security issues.")
        resources = tip.get("resources", {})

        owasp_url = resources.get("owasp", "https://owasp.org")
        portswigger_url = resources.get("portswigger", "https://portswigger.net")
        academy_url = resources.get("academy", "https://portswigger.net/web-security/all-labs")

        content = f"""[bold]What is this?[/bold]
{description}

[bold]Why does it matter?[/bold]
{why_matters}

[bold]How to verify manually:[/bold]
1. Identify the vulnerable parameter or endpoint
2. Craft a proof-of-concept (PoC) payload
3. Confirm the vulnerability with evidence (screenshots, requests/responses)
4. Document the impact clearly

[bold]Learn more:[/bold]
- [cyan]OWASP:[/cyan] {owasp_url}
- [cyan]PortSwigger:[/cyan] {portswigger_url}
- [cyan]Practice Labs:[/cyan] {academy_url}"""

        return Panel(
            content,
            title=f"[bold {color}]{vuln_name} - Clinic Tip[/bold {color}]",
            border_style=color,
            padding=(1, 2)
        )

    @classmethod
    def show_phase_tips(cls, findings: list):
        """
        Shows educational tips after a scan phase.
        Groups by vulnerability type to avoid repetition.
        """
        if not findings:
            console.print("[dim][Clinic] No findings to explain.[/dim]")
            return

        console.print("\n[bold yellow]══════════════════════════════════════[/bold yellow]")
        console.print("[bold yellow]  🏥 CLINIC TIPS — Learn as you hunt!  [/bold yellow]")
        console.print("[bold yellow]══════════════════════════════════════[/bold yellow]\n")

        # Group by vuln type to avoid repeats
        seen_types = set()
        for finding in findings:
            vuln_type = finding.get("finding_type", "Unknown")
            # Normalize type name for comparison
            norm_type = vuln_type.lower().strip()

            if norm_type not in seen_types:
                seen_types.add(norm_type)
                panel = cls.render_tip_panel(vuln_type, finding)
                console.print(panel)
                console.print()

        console.print("[dim]💡 Run 'aura learn <vuln_type>' for detailed remediation steps.[/dim]\n")

    @classmethod
    def list_vulnerability_types(cls) -> list:
        """Returns list of all available vulnerability types."""
        return list(cls.VULN_DATA.keys())

    @classmethod
    def get_severity_color(cls, severity: str) -> str:
        """Returns Rich color code for severity level."""
        colors = {
            "CRITICAL": "red bold",
            "HIGH": "yellow bold",
            "MEDIUM": "cyan",
            "LOW": "green",
            "INFO": "grey"
        }
        return colors.get(severity.upper(), "white")

    @classmethod
    def explain_severity(cls, severity: str) -> str:
        """Returns plain-English explanation of severity level."""
        explanations = {
            "CRITICAL": "Extremely serious. An attacker can completely take over the system or steal all data.",
            "HIGH": "Very serious. An attacker can gain significant access or steal sensitive data.",
            "MEDIUM": "Moderately serious. An attacker needs specific conditions or user interaction.",
            "LOW": "A minor issue. It may be hard to exploit or the impact is limited.",
            "INFO": "Informational. Not a vulnerability but useful intelligence."
        }
        return explanations.get(severity.upper(), "Unknown severity.")
