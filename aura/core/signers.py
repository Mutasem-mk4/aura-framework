import hmac
import hashlib
import time
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseSigner(ABC):
    """Abstract base class for target-specific request signers."""
    
    @abstractmethod
    def sign(self, method: str, url: str, headers: Dict[str, str], body: Any) -> Dict[str, str]:
        """Calculates the signature and returns updated headers."""
        pass

class CoinhakoSigner(BaseSigner):
    """
    Aura v25.0: Coinhako-specific signing logic.
    Implements ECDSA/secp256k1 signing structure.
    """
    def __init__(self, api_key: str, secret_key: str):
        self.api_key = api_key
        self.secret_key = secret_key

    def sign(self, method: str, url: str, headers: Dict[str, str], body: Any) -> Dict[str, str]:
        # Coinhako standard: key + nonce signed with secret
        nonce = str(int(time.time() * 1000))
        
        # This is where the specific ECDSA signing would happen.
        # We provide the structure to plug in the secret-based signature.
        # Placeholder for the actual cryptographic operation
        signature = "[GENERATED_SIGNATURE]" 
        
        updated_headers = headers.copy()
        updated_headers["x-api-key"] = self.api_key
        updated_headers["x-api-nonce"] = nonce
        updated_headers["x-api-signature"] = signature
        updated_headers["x-api-algorithm"] = "ecdsa-secp256k1-sha256"
        
        return updated_headers

class SignerManager:
    """Registry for target-specific signers."""
    _signers: Dict[str, BaseSigner] = {}

    @classmethod
    def register(cls, domain: str, signer: BaseSigner):
        cls._signers[domain] = signer

    @classmethod
    def get_signer(cls, url: str) -> Optional[BaseSigner]:
        for domain, signer in cls._signers.items():
            if domain in url:
                return signer
        return None
