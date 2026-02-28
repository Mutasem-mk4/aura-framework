class ComplianceMapper:
    """Maps finding types to MITRE ATT&CK and OWASP Top 10."""
    
    MAPPING = {
        "SQL Injection": {
            "owasp": "A03:2021-Injection",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "severity": "CRITICAL"
        },
        "Cross-Site Scripting (XSS)": {
            "owasp": "A03:2021-Injection",
            "mitre": "T1189 - Drive-by Compromise",
            "severity": "HIGH"
        },
        "SSRF": {
            "owasp": "A10:2021-Server-Side Request Forgery",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "severity": "HIGH"
        },
        "Exposed Credentials": {
            "owasp": "A07:2021-Identification and Authentication Failures",
            "mitre": "T1552 - Unsecured Credentials",
            "severity": "CRITICAL"
        },
        "S3 Bucket Public": {
            "owasp": "A05:2021-Security Misconfiguration",
            "mitre": "T1530 - Data from Cloud Storage Object",
            "severity": "HIGH"
        },
        "Subdomain Takeover": {
            "owasp": "A05:2021-Security Misconfiguration",
            "mitre": "T1584 - Compromise Infrastructure",
            "severity": "CRITICAL"
        },
        "Sensitive Data Exposure": {
            "owasp": "A04:2021-Insecure Design",
            "mitre": "T1592 - Gather Victim Host Information",
            "severity": "MEDIUM"
        }
    }

    @classmethod
    def get_compliance_data(cls, finding_type: str) -> dict:
        """Returns MITRE and OWASP info for a given finding type."""
        # Fuzzy matching logic
        for key, data in cls.MAPPING.items():
            if key.lower() in finding_type.lower() or finding_type.lower() in key.lower():
                return data
        
        return {
            "owasp": "A00:2021-Unknown",
            "mitre": "T0000 - General Technique",
            "severity": "INFO"
        }
