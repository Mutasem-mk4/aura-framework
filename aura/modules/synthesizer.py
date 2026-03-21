import asyncio
import socket
import uuid
from rich.console import Console
from typing import List, Dict, Any
from aura.core.engine_interface import IEngine
from aura.core.models import Finding, Severity

from aura.ui.formatter import console

class ProtocolSynthesizer(IEngine):
    """
    v16.1 OMNI-SOVEREIGN
    Universal Protocol Synthesizer - Multi-Protocol Fuzzing Engine.
    """
    ENGINE_ID = "protocol_synthesizer"

    def __init__(self, persistence=None, telemetry=None, brain=None, **kwargs):
        self.persistence = persistence
        self.telemetry = telemetry
        self.brain = brain
        self.known_protocols = {80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 3306: "MySQL"}
        self._status = "initialized"
        
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Unified entry point for IEngine."""
        self._status = "running"
        port = kwargs.get("port")
        if not port:
             # Default to 80 if not provided, though typically caller provides it
             port = 80
        
        findings = []
        res = await self.synthesize_and_fuzz(target, port)
        
        if res:
            findings.append(Finding(
                content=f"AI synthesized protocol on {target}:{port}. Type: {res.get('type')}. Vector: {res.get('vector')}",
                finding_type=f"Synthesized Protocol: {res.get('protocol')}",
                severity=Severity.MEDIUM,
                target_value=f"{target}:{port}",
                meta={"engine": self.ENGINE_ID, "raw": res}
            ))
            
        self._status = "completed"
        return findings

    def get_status(self) -> Dict[str, Any]:
        return {"id": self.ENGINE_ID, "status": self._status}

    async def synthesize_and_fuzz(self, ip, port):
        """AI analyzes binary stream to identify and fuzz unknown protocols."""
        console.print(f"[bold magenta][🧬] Synthesizer probing protocol on {ip}:{port}...[/bold magenta]")
        
        try:
            # Step 1: Binary Grab (Banner Grabbing v2)
            reader, writer = await asyncio.open_connection(ip, port)
            # Send a generic probe
            writer.write(b"\x00\x00\x00\x00")
            await writer.drain()
            
            data = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            
            if not data:
                console.print(f"[dim] No binary response from {ip}:{port}.[/dim]")
                return

            # Step 2: AI Structural Analysis
            analysis = self.brain.reason_json(
                f"Analyze this binary response from port {port}: {data.hex()}\n"
                "Identify: protocol_type, packet_structure, potential_vulnerabilities.\n"
                "Respond ONLY in JSON: {'protocol': 'str', 'type': 'str', 'vector': 'str'}"
            )
            
            import json
            res = json.loads(analysis)
            console.print(f"[bold green][+] Protocol Synthesized: {res.get('protocol')} ({res.get('type')})[/bold green]")
            console.print(f"[red][!] Potential Vector: {res.get('vector')}[/red]")
            
            return res
            
        except Exception as e:
             console.print(f"[dim red][!] Synthesizer error: {e}[/dim red]")
             return None
