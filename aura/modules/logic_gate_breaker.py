import asyncio
import json
from rich.console import Console
from aura.core import state

console = Console()

class LogicGateBreaker:
    """
    [FINANCIAL LOGIC SINGULARITY] v38.0: Morphic-Math Logic Fuzzer.
    Targets numeric parameters to discover Price Manipulation, Integer Overflows,
    and Parameter Pollution vulnerabilities.
    """
    def __init__(self, session=None):
        self.session = session

    async def run_audit(self, endpoints: list[dict]):
        """Audits every numeric parameter for logic flaws."""
        all_findings = []
        console.print(f"[bold cyan][⚔️ LOGIC GATE] Auditing {len(endpoints)} routes for Financial Logic flaws...[/bold cyan]")
        
        for ep in endpoints:
            numeric_params = [k for k, v in ep["params"].items() if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit())]
            if not numeric_params: continue
            
            for param in numeric_params:
                # 1. Negative Value Test (Price/Quantity Manipulation)
                res = await self._test_negative_value(ep, param)
                if res: all_findings.append(res)
                
                # 2. Integer Overflow Test
                res = await self._test_integer_overflow(ep, param)
                if res: all_findings.append(res)
                
                # 3. Parameter Pollution (Multi-Price Injection)
                res = await self._test_parameter_pollution(ep, param)
                if res: all_findings.append(res)
                
        return all_findings

    async def _test_negative_value(self, ep: dict, param: str):
        """Tests if the backend accepts negative numbers for price/quantity."""
        payload = ep["params"].copy()
        payload[param] = -9999
        try:
            resp = await self.session.request(ep["method"], ep["path"], json=payload)
            if resp and resp.status_code == 200:
                # Heuristic: If we sent -9999 and the server accepted it (200), check if it reflects
                if "-9999" in resp.text:
                    console.print(f"[bold red][💰 PRICE MANIPULATION] Possible on {ep['path']} | Param: {param}[/bold red]")
                    return {
                        "type": "Price/Quantity Manipulation (Negative Value)",
                        "severity": "CRITICAL", "url": ep["path"],
                        "content": f"Server accepted negative value (-9999) for parameter '{param}'. Potential financial loss."
                    }
        except: pass
        return None

    async def _test_integer_overflow(self, ep: dict, param: str):
        """Tests for 32/64-bit integer overflows."""
        overflow_val = 2147483648 # 2^31
        payload = ep["params"].copy()
        payload[param] = overflow_val
        try:
            resp = await self.session.request(ep["method"], ep["path"], json=payload)
            if resp and resp.status_code == 200:
                # Success might indicate improper handling or wrap-around
                return None # Requires deeper state analysis
        except: pass
        return None

    async def _test_parameter_pollution(self, ep: dict, param: str):
        """Sends price=100&price=0 (Parameter Pollution)."""
        # Note: For JSON, pollution often means sending the key twice or as an array
        payload = ep["params"].copy()
        payload[param] = [ep["params"][param], 0] # Attempt array-based pollution
        try:
            resp = await self.session.request(ep["method"], ep["path"], json=payload)
            if resp and resp.status_code == 200:
                if "0" in resp.text and str(ep["params"][param]) not in resp.text:
                    console.print(f"[bold red][⚓ PARAMETER POLLUTION] Confirmed on {ep['path']} | Param: {param}[/bold red]")
                    return {
                        "type": "Logical Parameter Pollution",
                        "severity": "HIGH", "url": ep["path"],
                        "content": f"Server prioritized the second (zeroed) value in parameter pollution for '{param}'."
                    }
        except: pass
        return None
