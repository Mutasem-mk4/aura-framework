import re
import ipaddress
from typing import List, Union

class ScopeManager:
    """Ghost v4: Operational Safety module for target scope validation."""
    
    def __init__(self, whitelist: List[str] = None, blacklist: List[str] = None):
        self.whitelist = whitelist or []
        self.blacklist = blacklist or []
        
    def is_in_scope(self, target: str) -> bool:
        """Checks if a target is within the allowed operational scope."""
        # 1. Check blacklist first (Explicitly Forbidden)
        if self._matches_list(target, self.blacklist):
            return False
            
        # 2. Check whitelist (If empty, everything except blacklist is allowed - Caution mode)
        if not self.whitelist:
            return True
            
        return self._matches_list(target, self.whitelist)

    def _matches_list(self, target: str, pattern_list: List[str]) -> bool:
        """Helper to check if target matches any CIDR, IP, or Regex in the list."""
        for pattern in pattern_list:
            # Check CIDR/IP
            if self._is_network_match(target, pattern):
                return True
            
            # Check Regex/Substring
            try:
                if re.search(pattern, target, re.IGNORECASE):
                    return True
            except re.error:
                if pattern.lower() in target.lower():
                    return True
                    
        return False

    def _is_network_match(self, target: str, network: str) -> bool:
        """Validates if target IP falls within a CIDR range."""
        try:
            # Check if network is actually a CIDR or IP
            net = ipaddress.ip_network(network, strict=False)
            tgt_ip = ipaddress.ip_address(target)
            return tgt_ip in net
        except ValueError:
            return False
