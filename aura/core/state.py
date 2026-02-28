# aura/core/state.py
import os

# Create the halt signal file in the root of the project to be accessible by all processes
HALT_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".aura_halt_signal")

# Global proxy configuration for Phase 5 Deep Proxy Architecture
PROXY_FILE = None

# Network Stability & Performance Scaling (Hyper-Acceleration Phase 19)
GLOBAL_CONCURRENCY_LIMIT = 10  # Increased for Protocol Warp parallelization
REQUEST_JITTER_MODE = True      # Forces subtle random delays to avoid triggering system-wide blocks

# Gemini AI Configuration
GEMINI_API_KEY = os.environ.get("AURA_GEMINI_API_KEY")
GEMINI_MODEL = "gemini-1.5-flash" # High-speed default for offensive operations

# OSINT API Keys (read from environment or .env)
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
OTX_API_KEY = os.environ.get("OTX_API_KEY")
CENSYS_API_ID = os.environ.get("CENSYS_API_ID")
CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET")
GREYNOISE_API_KEY = os.environ.get("GREYNOISE_API_KEY")

def is_halted():
    """Checks the filesystem for the halt signal marker."""
    return os.path.exists(HALT_FILE)

def emergency_stop():
    """Creates the halt signal marker to stop all active Aura processes."""
    try:
        with open(HALT_FILE, 'w') as f:
            f.write("HALTED")
    except Exception as e:
        print(f"Error writing halt state: {e}")

def reset_operations():
    """Removes the halt signal marker."""
    if os.path.exists(HALT_FILE):
        try:
            os.remove(HALT_FILE)
        except Exception as e:
            print(f"Error resetting state: {e}")

# Professional SOC Remediation Database
REMEDIATION_DB = {
    "SQL Injection": {
        "impact": "Critical",
        "impact_desc": "Unauthorized database access, data theft, or complete system compromise.",
        "fix": "Use parameterized queries (Prepared Statements) for all database interactions. Implement strict input validation.",
        "owasp": "A03:2021-Injection",
        "mitre": "T1190 - Exploit Public-Facing Application"
    },
    "Blind SQL Injection": {
        "impact": "Critical",
        "impact_desc": "Silent database exfiltration through timing or boolean inference. Extremely difficult to detect with traditional signatures.",
        "fix": "Ensure all database calls use type-safe abstractions. Implement rate-limiting and monitor for unusual request latency spikes.",
        "owasp": "A03:2021-Injection",
        "mitre": "T1059.006 - Python"
    },
    "Command Injection": {
        "impact": "Critical",
        "impact_desc": "Enables remote code execution (RCE) on the underlying host, leading to full server takeover.",
        "fix": "Avoid passing user input to system shells. Use built-in API functions that don't invoke a shell. Implement strict allow-listing.",
        "owasp": "A03:2021-Injection",
        "mitre": "T1059 - Command and Scripting Interpreter"
    },
    "AI-Verified Vulnerability": {
        "impact": "High",
        "impact_desc": "Heuristic detection of a complex vulnerability identified through behavioral reasoning.",
        "fix": "Review the specific logic findings provided in the Aura AI dossier. Manual verification of the identified attack path is recommended.",
        "owasp": "A00:2021-Unknown",
        "mitre": "T1595 - Active Scanning"
    },
    "XSS": {
        "impact": "High",
        "impact_desc": "Session hijacking, credential theft, and unauthorized actions on behalf of users.",
        "fix": "Implement Context-Aware Output Encoding. Use Content Security Policy (CSP) headers to restrict script execution.",
        "owasp": "A03:2021-Injection",
        "mitre": "T1189 - Drive-by Compromise"
    },
    "Subdomain Takeover": {
        "impact": "High",
        "fix": "Remove dangling DNS records (CNAME) pointing to unused external services.",
        "mitre": "T1584.004 - DNS Server"
    },
    "Exposed Secrets": {
        "impact": "Critical",
        "impact_desc": "Complete loss of control over critical cloud infrastructure or internal tools.",
        "fix": "Revoke leaked credentials immediately. Use environment variables or secret management vaults (e.g., HashiCorp Vault).",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "mitre": "T1552 - Unsecured Credentials"
    },
    "Credential-Leak": {
        "impact": "Critical",
        "impact_desc": "Unauthorized access to user accounts and exposure of sensitive personal information.",
        "fix": "Leaked credentials found in breaches. Force password resets, enable 2FA, and monitor for unauthorized access.",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "mitre": "T1589.001 - Credentials"
    },
    "Leak-Match": {
        "impact": "Critical",
        "impact_desc": "Immediate and verified risk of unauthorized service access or lateral movement.",
        "fix": "Direct match found in historical leaks. Immediate rotation of affected service credentials is required.",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "mitre": "T1589.001 - Credentials"
    },
    "S3 Bucket Leak": {
        "impact": "High",
        "impact_desc": "Bulk data exposure including documents, backups, and sensitive intellectual property.",
        "fix": "Review S3 Bucket Policies and ACLs. Ensure 'Block Public Access' is enabled at the account level.",
        "owasp": "A05:2021-Security Misconfiguration",
        "mitre": "T1530 - Data from Cloud Storage"
    },
    "SSRF": {
        "impact": "High",
        "impact_desc": "Internal network scanning, access to metadata services, and potential RCE.",
        "fix": "Implement allow-listing for outbound requests. Avoid passing user-controlled input directly into URL fetchers.",
        "owasp": "A10:2021-Server-Side Request Forgery",
        "mitre": "T1571 - Non-Standard Port"
    },
    "High Entropy": {
        "impact": "Critical",
        "impact_desc": "Exposure of sensitive keys used for encryption, authentication, or cloud management.",
        "fix": "High-entropy string detected (possible private key or token). Rotate the affected secret and move to a secure secret management system.",
        "owasp": "A02:2021-Cryptographic Failures",
        "mitre": "T1552 - Unsecured Credentials"
    },
    "JWT Weakness": {
        "impact": "High",
        "impact_desc": "Session impersonation through weak signing keys or insecure header algorithms.",
        "fix": "Use strong, asymmetric signing algorithms (e.g., RS256). Validate all JWT claims and avoid 'none' algorithm.",
        "owasp": "A02:2021-Cryptographic Failures",
        "mitre": "T1550.004 - Access Token"
    },
    "IDOR": {
        "impact": "High",
        "impact_desc": "Unauthorized access to other users' data by manipulating resource identifiers.",
        "fix": "Implement object-level access control checks. Use non-sequential/randomized IDs (UUIDs).",
        "owasp": "A01:2021-Broken Access Control",
        "mitre": "T1020 - Automated Exfiltration"
    },
    "Suspicious Behavioral Anomaly": {
        "impact": "Info",
        "impact_desc": "Identified behavior that suggests a potential vulnerability or WAF-bypass success but requires human verification.",
        "fix": "Review the AI Reasoning logs in the Aura Dossier. Perform manual timing analysis or boolean inference testing on the affected parameter.",
        "owasp": "A00:2021-Unknown",
        "mitre": "T1595 - Active Scanning"
    },
    "Singularity Discovery": {
        "impact": "High",
        "impact_desc": "Autonomous detection of a hidden or complex vulnerability via AI Chain-of-Thought reasoning.",
        "fix": "Manual verification of the AI-identified attack path is required. Review intercepted network logs for further context.",
        "owasp": "A04:2021-Insecure Design",
        "mitre": "T1595 - Active Scanning"
    },
    "Logic Flaw": {
        "impact": "High",
        "impact_desc": "Business logic failure identified through AI contextual reasoning. Can lead to privilege escalation or data exposure.",
        "fix": "Implement strict server-side validation for all business logic transitions. Ensure state-aware authorization for every request.",
        "owasp": "A04:2021-Insecure Design",
        "mitre": "T1548 - Abuse Elevation Control Mechanism"
    },
    "Information Disclosure": {
        "impact": "Medium",
        "impact_desc": "Exposure of system metadata or internal file structures which could aid an attacker in identifying high-value targets.",
        "fix": "Disable directory listing and protect sensitive files with strict access control lists (ACLs). Remove temporary or backup files from production.",
        "owasp": "A01:2021-Broken Access Control",
        "mitre": "T1592 - Gather Victim Host Information"
    },
    "Critical Path Discovery": {
        "impact": "Critical",
        "impact_desc": "Exposure of critical administrative or backup assets (e.g., /phpmyadmin, /backup, /db) leading to imminent system-level compromise.",
        "fix": "Immediately restrict access to management interfaces and move backup assets to secure, non-public storage. Implement multi-factor authentication and IP whitelisting.",
        "owasp": "A01:2021-Broken Access Control",
        "mitre": "T1078 - Valid Accounts"
    }
}

# Mission Methodology Definitions for Professional Reporting
SCAN_METHODOLOGY = {
    "Reconnaissance": "Passive discovery of subdomains, IP space, and DNS records using global OSINT and rapid-fire active resolution.",
    "Intelligence": "Aggregating threat intelligence from Shodan, Censys, and VirusTotal to map the target's attack surface and WAF presence.",
    "Visual Analysis": "Deep-learning based visual inspection of web interfaces to identify technology stacks and sensitive entry points.",
    "Vulnerability Discovery": "Humanized DAST routines combined with entropy-based secret hunting and automated CVE correlation.",
    "Exploitation": "Context-aware automated exploitation and iterative AI-driven debugging of zero-day proof-of-concepts."
}

# Supported OSINT Sources for Coverage Tracking
OSINT_SOURCES = ["Shodan", "VirusTotal", "AlienVault OTX", "Censys", "GreyNoise"]

class WorkflowTracker:
    """Phase 29: Tracks multi-step transactions (e.g., checkout flows) to detect stateful flaws."""
    def __init__(self):
        self.transactions = [] # List of {'url': str, 'method': str, 'params': dict, 'cookies': dict}
        self.active_session_cookies = {}

    def record_step(self, url: str, method: str, params: dict, cookies: dict):
        self.transactions.append({
            "url": url,
            "method": method,
            "params": params,
            "cookies": cookies.copy()
        })
        if cookies:
            self.active_session_cookies.update(cookies)

    def get_last_transaction(self):
        return self.transactions[-1] if self.transactions else None

    def clear(self):
        self.transactions = []
        self.active_session_cookies = {}
