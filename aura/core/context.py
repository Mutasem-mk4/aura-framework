"""
Aura Framework - Context & Configuration Module

This module replaces global mutable state with strict, type-safe Configuration
and Mission Context objects. It ensures safe concurrency, determinism, and 
clean dependency injection across the pipeline.
"""

import os
import asyncio
from typing import Dict, List, Optional, Set, Any
from pydantic import BaseModel, Field, SecretStr, PrivateAttr


class AuraConfig(BaseModel):
    """
    Static system configuration, API keys, and global preferences.
    This should be instantiated once at startup and treated as immutable.
    """
    # Network & Stealth
    proxy_file: Optional[str] = None
    tor_mode: bool = False
    tor_port: int = 9050
    smart_bypass: bool = True
    global_concurrency_limit: int = Field(default=3, description="Max concurrent requests (Intigriti compliance)")
    request_jitter_mode: bool = True
    network_timeout: int = 30
    oast_poll_interval: int = 15
    
    # AI & Providers
    gemini_api_key: Optional[SecretStr] = None
    gemini_model: str = "gemini-2.0-flash"
    ollama_host: Optional[str] = None
    ollama_model: str = "qwen2.5-coder:7b"
    openrouter_api_key: Optional[SecretStr] = None
    zenith_free_stack: List[str] = Field(default_factory=lambda: [
        "google/gemini-2.0-flash-exp:free",
        "meta-llama/llama-3.3-70b-instruct:free",
        "mistralai/mistral-7b-instruct:free",
        "openrouter/auto"
    ])

    # OSINT API Keys
    shodan_api_key: Optional[SecretStr] = None
    virustotal_api_key: Optional[SecretStr] = None
    otx_api_key: Optional[SecretStr] = None
    censys_api_id: Optional[SecretStr] = None
    censys_api_secret: Optional[SecretStr] = None
    greynoise_api_key: Optional[SecretStr] = None
    securitytrails_api_key: Optional[SecretStr] = None
    binaryedge_api_key: Optional[SecretStr] = None
    intelx_api_key: Optional[SecretStr] = None
    hunterio_api_key: Optional[SecretStr] = None
    fullhunt_api_key: Optional[SecretStr] = None
    
    # Cloud & Platforms
    digitalocean_token: Optional[SecretStr] = None
    bounty_platform: str = "hackerone"
    
    # Reporting
    custom_consultant: str = "Independent Security Researcher"
    custom_company: str = "Security Assessment Team"

    @classmethod
    def from_env(cls) -> "AuraConfig":
        """Factory to build config directly from environment variables."""
        return cls(
            gemini_api_key=SecretStr(os.environ["GEMINI_API_KEY"]) if os.environ.get("GEMINI_API_KEY") else None,
            ollama_host=os.environ.get("OLLAMA_HOST"),
            ollama_model=os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b"),
            openrouter_api_key=SecretStr(os.environ["OPENROUTER_API_KEY"]) if os.environ.get("OPENROUTER_API_KEY") else None,
            shodan_api_key=SecretStr(os.environ["SHODAN_API_KEY"]) if os.environ.get("SHODAN_API_KEY") else None,
            virustotal_api_key=SecretStr(os.environ["VIRUSTOTAL_API_KEY"]) if os.environ.get("VIRUSTOTAL_API_KEY") else None,
            otx_api_key=SecretStr(os.environ["OTX_API_KEY"]) if os.environ.get("OTX_API_KEY") else None,
            censys_api_id=SecretStr(os.environ["CENSYS_API_ID"]) if os.environ.get("CENSYS_API_ID") else None,
            censys_api_secret=SecretStr(os.environ["CENSYS_API_SECRET"]) if os.environ.get("CENSYS_API_SECRET") else None,
            greynoise_api_key=SecretStr(os.environ["GREYNOISE_API_KEY"]) if os.environ.get("GREYNOISE_API_KEY") else None,
            securitytrails_api_key=SecretStr(os.environ["SECURITYTRAILS_API_KEY"]) if os.environ.get("SECURITYTRAILS_API_KEY") else None,
            binaryedge_api_key=SecretStr(os.environ["BINARYEDGE_API_KEY"]) if os.environ.get("BINARYEDGE_API_KEY") else None,
            intelx_api_key=SecretStr(os.environ["INTELX_API_KEY"]) if os.environ.get("INTELX_API_KEY") else None,
            hunterio_api_key=SecretStr(os.environ["HUNTERIO_API_KEY"]) if os.environ.get("HUNTERIO_API_KEY") else None,
            fullhunt_api_key=SecretStr(os.environ["FULLHUNT_API_KEY"]) if os.environ.get("FULLHUNT_API_KEY") else None,
            digitalocean_token=SecretStr(os.environ["DIGITALOCEAN_TOKEN"]) if os.environ.get("DIGITALOCEAN_TOKEN") else None,
            bounty_platform=os.environ.get("BOUNTY_PLATFORM", "hackerone")
        )


class FeatureFlags(BaseModel):
    """Runtime execution flags defining the operational mode of the mission."""
    cloud_swarm_mode: bool = False
    fast_mode: bool = False
    auto_submit: bool = False
    apex_mode: bool = False
    ghost_mode: bool = False
    beginner_mode: bool = True
    clinic_mode: bool = False
    openrouter_free_mode: bool = False


class WorkflowTracker(BaseModel):
    """Tracks multi-step transactions (e.g., checkout flows) to detect stateful flaws."""
    transactions: List[Dict[str, Any]] = Field(default_factory=list)
    active_session_cookies: Dict[str, str] = Field(default_factory=dict)

    def record_step(self, url: str, method: str, params: dict, cookies: dict):
        self.transactions.append({
            "url": url,
            "method": method,
            "params": params,
            "cookies": cookies.copy() if cookies else {}
        })
        if cookies:
            self.active_session_cookies.update(cookies)

    def get_last_transaction(self) -> Optional[Dict[str, Any]]:
        return self.transactions[-1] if self.transactions else None


class MissionContext(BaseModel):
    """
    Encapsulates all state, configuration, and data for a specific scanning target.
    This object is passed down the pipeline, ensuring concurrency safety.
    """
    target_url: str
    config: AuraConfig = Field(default_factory=AuraConfig.from_env)
    flags: FeatureFlags = Field(default_factory=FeatureFlags)
    
    # Mission-specific network state
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    custom_cookies: Dict[str, str] = Field(default_factory=dict)
    
    # Dual-Session Tokens (BOLA / IDOR)
    auth_token_attacker: Optional[str] = None
    auth_token_victim: Optional[str] = None
    
    # Operational State
    workflow_tracker: WorkflowTracker = Field(default_factory=WorkflowTracker)
    dns_failure_cache: Set[str] = Field(default_factory=set)
    discovered_urls: Set[str] = Field(default_factory=set)
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Concurrency Safety lock
    _lock: asyncio.Lock = PrivateAttr(default_factory=asyncio.Lock)

    async def add_url(self, url: str):
        """Thread-safe URL addition."""
        async with self._lock:
            self.discovered_urls.add(url)

    async def add_vulnerability(self, vuln: Dict[str, Any]):
        """Thread-safe vulnerability addition."""
        async with self._lock:
            self.vulnerabilities.append(vuln)

    def mark_dns_failed(self, host: str):
        """Mark a host as unresolvable for this specific mission."""
        bare = host.split(':')[0]
        if bare:
            self.dns_failure_cache.add(bare)

    def is_dns_failed(self, host: str) -> bool:
        """Check if a host is marked as unresolvable in this mission."""
        bare = host.split(':')[0]
        return bare in self.dns_failure_cache

    class Config:
        arbitrary_types_allowed = True
