import os
from typing import Dict, Optional, Any

class MissionContext:
    """
    Encapsulates mission-specific configuration and state.
    Replaces global variables in state.py to ensure concurrency safety.
    """
    def __init__(self, target: str, args: Optional[Any] = None, **kwargs):
        self.target = target
        
        # Network & Performance
        self.concurrency_limit = kwargs.get('concurrency_limit', 3)
        self.jitter_mode = kwargs.get('jitter_mode', True)
        self.timeout = kwargs.get('timeout', 30)
        self.fast_mode = kwargs.get('fast_mode', False)
        
        # Auth & Headers
        self.custom_headers: Dict[str, str] = kwargs.get('custom_headers', {})
        self.custom_cookies: Dict[str, str] = kwargs.get('custom_cookies', {})
        self.auth_token_attacker = kwargs.get('auth_token_attacker') or os.environ.get("AUTH_TOKEN_ATTACKER")
        self.auth_token_victim = kwargs.get('auth_token_victim') or os.environ.get("AUTH_TOKEN_VICTIM")
        
        # State Tracking
        self.discovered_urls = set()
        self.dns_failures = set()
        self.findings = []
        
        # Extract from args if provided (CLI integration)
        if args:
            if hasattr(args, 'fast'):
                self.fast_mode = args.fast
            if hasattr(args, 'auto_submit'):
                self.auto_submit = args.auto_submit
                
    def mark_dns_failed(self, host: str):
        bare = host.split(':')[0]
        if bare:
            self.dns_failures.add(bare)
            
    def is_dns_failed(self, host: str) -> bool:
        bare = host.split(':')[0]
        return bare in self.dns_failures
