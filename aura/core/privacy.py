import re
import json
from typing import Any, Union

class PrivacyFilter:
    """
    Aura v25.0: Automatic Sensitive Data Redaction.
    Ensures that credentials, tokens, and PII are never logged or printed.
    """
    
    # Standard patterns for redaction
    PATTERNS = {
        "Authorization": r'(Authorization:\s*)(Bearer\s+|Basic\s+)?[A-Za-z0-9-_=.]+',
        "Cookie": r'(Cookie:\s*)[^;\n\r]+',
        "JWT": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
        "API_Key": r'(x-api-key:\s*)[A-Za-z0-9-_]+',
        "Generic_Token": r'([Tt]oken|[Ss]ecret|[Ss]ignature)["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{16,}["\']?'
    }

    @classmethod
    def redact(cls, text: str) -> str:
        """Applies all redaction patterns to the provided text."""
        if not isinstance(text, str):
            return str(text)
            
        redacted = text
        for name, pattern in cls.PATTERNS.items():
            # For header-like patterns, we use capturing groups to keep the label but hide the value
            if "(" in pattern:
                redacted = re.sub(pattern, r'\1[REDACTED]', redacted, flags=re.IGNORECASE)
            else:
                redacted = re.sub(pattern, f'[REDACTED_{name}]', redacted)
        
        return redacted

    @classmethod
    def mask_dict(cls, data: dict) -> dict:
        """Recursively masks sensitive keys in a dictionary."""
        if not isinstance(data, dict):
            return data
            
        masked = {}
        sensitive_keys = {"authorization", "cookie", "token", "secret", "key", "signature", "password"}
        
        for k, v in data.items():
            if k.lower() in sensitive_keys:
                masked[k] = "[REDACTED]"
            elif isinstance(v, dict):
                masked[k] = cls.mask_dict(v)
            elif isinstance(v, list):
                masked[k] = [cls.mask_dict(i) if isinstance(i, dict) else i for i in v]
            else:
                masked[k] = v
        return masked

def aura_print(text: Any, console=None):
    """Wrapper for printing that automatically applies the privacy filter."""
    filtered_text = PrivacyFilter.redact(str(text))
    if console:
        console.print(filtered_text)
    else:
        print(filtered_text)
