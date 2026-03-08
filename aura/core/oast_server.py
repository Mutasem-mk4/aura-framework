import asyncio
import uuid
import logging
import json
import base64
import random
import string
from typing import Dict, List, Optional
import aiohttp
from rich.console import Console

logger = logging.getLogger("aura")
console = Console()

class OASTClient:
    """
    v38.0: The OAST Subsystem (Out-of-Band Application Security Testing)
    Provides unique callback URLs and polls for asynchronous interactions 
    (DNS, HTTP, SMTP) to detect blind vulnerabilities.
    """
    
    DEFAULT_SERVERS = ["interactsh.com", "oast.pro", "oast.live", "oast.site", "oast.online"]
    
    def __init__(self, server: Optional[str] = None):
        self.server = server or random.choice(self.DEFAULT_SERVERS)
        self.session_id = str(uuid.uuid4()).replace("-", "")[:20]
        self.correlation_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        self.correlation_url = f"{self.correlation_id}.{self.server}"
        self.active = False
        self.interactions = []
        self.mapping = {} # correlation_id -> {module, target_url}

    async def initialize(self):
        """Initializes the OAST session (Simulated for Now, can be extended to full interactsh registration)."""
        console.print(f"[bold cyan][*] OAST: Subsystem initialized on {self.server}[/bold cyan]")
        console.print(f"[cyan][*] OAST: Base Callback Domain: {self.correlation_url}[/cyan]")
        self.active = True
        return True

    def get_payload(self, module_name: str, target_url: str) -> str:
        """Generates a unique sub-domain payload for a specific injection point."""
        unique_token = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        full_url = f"{unique_token}.{self.correlation_url}"
        self.mapping[unique_token] = {
            "module": module_name,
            "target": target_url
        }
        return full_url

    async def poll(self, db_callback=None):
        """
        Polls the OAST server for new interactions.
        In a real scenario, this would call the interactsh API with the session secret.
        For this implementation, we provide the architecture for polling.
        """
        if not self.active:
            return

        # logger.debug(f"OAST: Polling {self.server} for interactions...")
        
        # Real implementation would perform an authenticated GET request to the OAST server
        # For the prototype, we simulate checking a queue.
        # await self._real_poll_logic(db_callback)
        pass

    async def _real_poll_logic(self, db_callback):
        """Placeholder for actual Interactsh API polling logic."""
        # async with aiohttp.ClientSession() as session:
        #     async with session.get(f"https://{self.server}/poll?id={self.session_id}") as resp:
        #         if resp.status == 200:
        #             data = await resp.json()
        #             for inter in data.get("interactions", []):
        #                 await self._process_interaction(inter, db_callback)
        pass

    async def _process_interaction(self, inter: Dict, db_callback):
        """Processes a single interaction and maps it back to a finding."""
        full_host = inter.get("full-id", "")
        # Extract the unique_token (the first part of the subdomain)
        unique_token = full_host.split(".")[0]
        
        if unique_token in self.mapping:
            context = self.mapping[unique_token]
            finding = {
                "type": f"Blind Vulnerability ({inter.get('protocol', 'Unknown').upper()})",
                "severity": "CRITICAL",
                "content": f"OAST Interaction detected from {inter.get('remote-address')}\n"
                           f"Module: {context['module']}\n"
                           f"Target URL: {context['target']}\n"
                           f"Protocol: {inter.get('protocol')}\n"
                           f"Raw Request: {inter.get('raw-request', 'N/A')}",
                "confirmed": True
            }
            if db_callback:
                await db_callback(context['target'], finding)
            console.print(f"[bold red][![OAST]] CRITICAL: {finding['type']} confirmed on {context['target']}![/bold red]")

class OASTManager:
    """Singleton-like manager for OAST access across Aura modules."""
    _instance = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = OASTClient()
        return cls._instance
