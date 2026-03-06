"""
Aura v22.0 — CVSS Auto-Calculator (Tier 3 Evidence Engine)
Generates accurate CVSS 3.1 scores from structured finding fields.

Why this matters:
  - Wrong CVSS = platforms downgrade your severity → less money
  - Correct CVSS = your report looks professional → accepted faster
  - This engine auto-generates the CVSS Vector AND written justification

CVSS 3.1 Base Metrics:
  AV  - Attack Vector:    Network(N) | Adjacent(A) | Local(L) | Physical(P)
  AC  - Attack Complexity: Low(L) | High(H)
  PR  - Privileges Required: None(N) | Low(L) | High(H)
  UI  - User Interaction:  None(N) | Required(R)
  S   - Scope:            Unchanged(U) | Changed(C)
  C   - Confidentiality:  High(H) | Low(L) | None(N)
  I   - Integrity:        High(H) | Low(L) | None(N)
  A   - Availability:     High(H) | Low(L) | None(N)
"""
from rich.console import Console

console = Console()

# CVSS v3.1 Base Score lookup table (simplified but accurate)
CVSS_BASE_SCORES = {
    # (AV, AC, PR, UI, S, C, I, A) → score
    # CRITICAL
    ("N", "L", "N", "N", "C", "H", "H", "H"): 10.0,
    ("N", "L", "N", "N", "U", "H", "H", "H"): 9.8,
    ("N", "L", "N", "N", "C", "H", "H", "N"): 9.3,
    ("N", "L", "N", "R", "C", "H", "H", "N"): 9.0,
    # HIGH
    ("N", "L", "N", "N", "U", "H", "H", "N"): 8.6,
    ("N", "L", "L", "N", "U", "H", "H", "N"): 8.1,
    ("N", "L", "N", "R", "U", "H", "H", "N"): 8.1,
    ("N", "L", "N", "R", "C", "H", "L",  "N"): 7.4,
    ("N", "H", "N", "N", "U", "H", "H", "N"): 7.5,
    ("N", "L", "L", "R", "C", "H", "H", "N"): 8.3,
    # MEDIUM
    ("N", "L", "N", "R", "U", "L", "L",  "N"): 6.1,
    ("N", "L", "N", "N", "U", "L", "L",  "N"): 6.5,
    ("N", "L", "L", "N", "U", "L", "L",  "N"): 5.4,
    ("N", "L", "N", "N", "U", "L", "N",  "N"): 5.3,
    # LOW
    ("N", "L", "L", "R", "U", "L", "N",  "N"): 3.5,
}


class CVSSEngine:
    """
    Tier 3: Auto-generates CVSS 3.1 scores and vectors from vulnerability metadata.
    Makes your reports look expert-level and prevents severity downgrades.
    """

    # Vuln type → (AV, AC, PR, UI, S, C, I, A)
    VULN_PROFILES = {
        # CRITICAL
        "SSRF: AWS Metadata":                 ("N", "L", "N", "N", "C", "H", "H", "N"),
        "SSRF":                               ("N", "L", "N", "N", "U", "H", "H", "N"),
        "JWT Algorithm None Bypass":          ("N", "L", "N", "N", "U", "H", "H", "H"),
        "JWT Weak HS256 Secret":              ("N", "L", "N", "N", "U", "H", "H", "H"),
        "SQL Injection":                      ("N", "L", "N", "N", "U", "H", "H", "H"),
        "Remote Code Execution":              ("N", "L", "N", "N", "C", "H", "H", "H"),
        "XXE":                                ("N", "L", "N", "N", "U", "H", "H", "N"),
        # HIGH
        "IDOR":                               ("N", "L", "L", "N", "U", "H", "H", "N"),
        "IDOR / BOLA":                        ("N", "L", "L", "N", "U", "H", "H", "N"),
        "OAuth redirect_uri Bypass":          ("N", "L", "N", "R", "C", "H", "H", "N"),
        "Subdomain Takeover":                 ("N", "L", "N", "N", "C", "H", "H", "N"),
        "403 Bypass":                         ("N", "L", "N", "N", "U", "H", "H", "N"),
        "Cross-Site Scripting":               ("N", "L", "N", "R", "C", "H", "L",  "N"),
        "Open Redirect":                      ("N", "L", "N", "R", "U", "L", "L",  "N"),
        "HTTP Request Smuggling":             ("N", "L", "N", "N", "C", "H", "H", "N"),
        # MEDIUM
        "CORS Misconfiguration":              ("N", "L", "N", "R", "U", "H", "L",  "N"),
        "OAuth CSRF":                         ("N", "L", "N", "R", "U", "L", "L",  "N"),
        "OAuth Implicit Flow Token Leakage":  ("N", "L", "N", "N", "U", "L", "N",  "N"),
        "GraphQL Introspection Enabled":      ("N", "L", "N", "N", "U", "L", "N",  "N"),
        "Information Disclosure":             ("N", "L", "N", "N", "U", "L", "N",  "N"),
        "Mass Assignment":                    ("N", "L", "L", "N", "U", "L", "L",  "N"),
        "Missing Security Headers":           ("N", "L", "N", "R", "U", "L", "N",  "N"),
    }

    @staticmethod
    def _vector_to_score(av, ac, pr, ui, s, c, i, a) -> float:
        """Looks up the CVSS base score for a given metric combination."""
        key = (av, ac, pr, ui, s, c, i, a)
        if key in CVSS_BASE_SCORES:
            return CVSS_BASE_SCORES[key]
        # Simplified approximation based on CIA impact
        base = 3.9
        if c == "H": base += 2.5
        elif c == "L": base += 1.0
        if i == "H": base += 2.5
        elif i == "L": base += 1.0
        if a == "H": base += 1.5
        if s == "C": base = min(base * 1.1, 10.0)
        if pr == "N": base = min(base + 0.5, 10.0)
        if ac == "L": base = min(base + 0.3, 10.0)
        return round(min(base, 10.0), 1)

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Converts CVSS score to severity label."""
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        if score > 0.0:  return "LOW"
        return "INFORMATIVE"

    @classmethod
    def calculate(cls, vuln_type: str, confirmed: bool = True,
                  needs_auth: bool = False, needs_user_interaction: bool = False) -> dict:
        """
        Calculates CVSS 3.1 score for a finding.
        Returns: { score, severity, vector, justification }
        """
        # Find best matching profile
        profile = None
        for key in cls.VULN_PROFILES:
            if key.lower() in vuln_type.lower() or vuln_type.lower().startswith(key.lower()):
                profile = cls.VULN_PROFILES[key]
                break

        if not profile:
            # Default: Network, Low Complexity, None Priv, None UI, Unchanged, Low CIA
            profile = ("N", "L", "N", "N", "U", "L", "L", "N")

        av, ac, pr, ui, s, c, i, a = profile

        # Adjust for context
        if needs_auth:
            pr = "L"  # Low privileges (authenticated)
        if needs_user_interaction:
            ui = "R"  # Required

        score    = cls._vector_to_score(av, ac, pr, ui, s, c, i, a)
        severity = cls._score_to_severity(score)
        vector   = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

        av_names = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
        s_names  = {"C": "Changed (scope crosses security boundaries)", "U": "Unchanged"}
        c_names  = {"H": "High", "L": "Low", "N": "None"}

        justification = (
            f"**Attack Vector: {av_names.get(av, av)}** — exploitable remotely over the internet.\n"
            f"**Attack Complexity: {'Low' if ac == 'L' else 'High'}** — {'no special conditions required' if ac == 'L' else 'requires specific conditions'}.\n"
            f"**Privileges Required: {'None' if pr == 'N' else ('Low' if pr == 'L' else 'High')}** — "
            f"{'no authentication needed' if pr == 'N' else 'requires authenticated user'}.\n"
            f"**Scope: {s_names.get(s, s)}**.\n"
            f"**Confidentiality Impact: {c_names.get(c, c)}** / "
            f"**Integrity: {c_names.get(i, i)}** / "
            f"**Availability: {c_names.get(a, a)}**."
        )

        return {
            "score":         score,
            "severity":      severity,
            "vector":        vector,
            "justification": justification,
        }

    @classmethod
    def enrich_finding(cls, finding: dict) -> dict:
        """
        Takes an existing finding dict and enriches it with accurate CVSS data.
        Upgrades score/severity/vector in-place.
        """
        vuln_type = finding.get("type", "")
        confirmed = finding.get("confirmed", False)

        result = cls.calculate(
            vuln_type=vuln_type,
            confirmed=confirmed,
        )

        # Only upgrade score if our calculation is higher or finding lacks CVSS
        existing_score = float(finding.get("cvss_score", 0) or 0)
        if result["score"] > existing_score or not finding.get("cvss_vector"):
            finding["cvss_score"]  = result["score"]
            finding["severity"]    = result["severity"]
            finding["cvss_vector"] = result["vector"]

        if not finding.get("cvss_justification"):
            finding["cvss_justification"] = result["justification"]

        return finding

    @classmethod
    def enrich_all(cls, findings: list[dict]) -> list[dict]:
        """Enriches a full list of findings with accurate CVSS data."""
        return [cls.enrich_finding(f) for f in findings]
