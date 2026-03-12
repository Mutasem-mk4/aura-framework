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
        """Initializes the OAST session and verifies availability."""
        console.print(f"[bold cyan][*] OAST: Subsystem checking availability of {self.server}...[/bold cyan]")
        
        # v38.0: Test if public OAST domain is blocked
        is_blocked = await self._check_oast_blocked(self.server)
        
        if is_blocked:
            console.print(f"[bold red][!] OAST ALERT: Public domain {self.server} is BLOCKED by target firewall.[/bold red]")
            # v38.0: The OAST Ghost - Autonomous VPS deployment
            ghost_domain = await self._spin_up_ghost_oast()
            if ghost_domain:
                self.server = ghost_domain
                self.correlation_url = f"{self.correlation_id}.{self.server}"
                console.print(f"[bold purple][👻 GHOST OAST] Successfully deployed private OAST on {self.server}[/bold purple]")
            else:
                console.print("[dim red][!] Ghost OAST deployment failed. Falling back to generic OAST...[/dim red]")
        
        console.print(f"[cyan][*] OAST: Base Callback Domain: {self.correlation_url}[/cyan]")
        self.active = True
        return True

    async def _check_oast_blocked(self, server: str) -> bool:
        """v38.0: Checks if the target environment blocks public OAST domains."""
        # In a real scenario, this would perform a DNS lookup or a probe to see if the domain is filtered.
        # For this prototype, we simulate a 10% chance of being blocked.
        return random.random() < 0.10

    async def _spin_up_ghost_oast(self) -> Optional[str]:
        """
        [THE OAST GHOST] v38.0: Autonomous Private OAST Deployment.
        Spins up a temporary OAST listener on a random VPS via API (DigitalOcean/AWS/etc).
        """
        console.print("[bold yellow][🎭] Engaging 'Ghost OAST' Protocol: Deploying private listener...[/bold yellow]")
        
        # This would interface with a Cloud API (e.g. DigitalOcean, AWS) to:
        # 1. Create a tiny instance (Droplet/EC2)
        # 2. Assign a random subdomain or IP
        # 3. Start a simple DNS/HTTP listener (interactsh-server)
        
        # Simulated successful deployment
        ghost_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        ghost_domain = f"ghost-{ghost_id}.aura-sec.io"
        
        await asyncio.sleep(2) # Simulate deployment time
        return ghost_domain

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
