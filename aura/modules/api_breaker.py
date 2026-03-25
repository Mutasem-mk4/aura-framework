import asyncio
import json
import random
import yaml
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin

from aura.ui.formatter import console

class APIBreaker:
    """
    v31.0: The API Breaker
    Discovers, parses, and exploits hidden REST/GraphQL API specifications (Swagger, OpenAPI).
    Focuses on BOLA/IDOR by synthesizing dynamic valid requests.
    """
    def __init__(self, session):
        self.session = session
        self.schema_endpoints = [
            "/swagger.json", "/api/swagger.json", "/v1/swagger.json", "/v2/swagger.json",
            "/v3/swagger.json", "/openapi.json", "/api/openapi.json", "/docs/openapi.json",
            "/swagger.yaml", "/api/swagger.yaml", "/openapi.yaml", "/docs/swagger.json",
            "/api-docs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/swagger/v1/swagger.json", "/swagger/v2/swagger.json", "/api/v1/swagger.json",
            "/spec.json", "/api-docs/swagger.json"
        ]
        self.common_parameters = {
            "id": ["1", "2", "3", "100", "999", "admin", "test"],
            "user_id": ["1", "2", "3", "100", "999"],
            "account_id": ["1", "2", "3", "ACC-1", "ACC-2"],
            "email": ["test@example.com", "admin@example.com"],
            "username": ["admin", "test", "user1"],
            "role": ["user", "admin", "manager"],
        }
        self.payload_signatures = [
            "' OR 1=1 --",
            "<script>alert(1)</script>",
            "{{7*7}}",
            "../" * 5 + "etc/passwd"
        ]

    async def probe_schemas(self, base_url: str) -> List[Dict[str, Any]]:
        """Scans for exposed API schemas on the target."""
        console.print(f"[bold cyan][*] API Breaker: Initiating schema discovery on {base_url}...[/bold cyan]")
        schemas = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Concurrently probe all common schema locations
        tasks = []
        for path in self.schema_endpoints:
            url = urljoin(base, path)
            tasks.append(self._fetch_schema(url))
            
        results = await asyncio.gather(*tasks)
        for url, data in results:
            if data:
                schemas.append({"url": url, "data": data})
                console.print(f"[bold red][!] API Breaker: Found exposed API Schema: {url}[/bold red]")
                
        return schemas

    async def _fetch_schema(self, url: str) -> tuple:
        """Fetches and attempts to parse a schema file (JSON or YAML)."""
        try:
            resp = await self.session.get(url, timeout=10)
            if not resp or resp.status_code != 200:
                return url, None
                
            content_type = resp.headers.get("Content-Type", "").lower()
            text = resp.text
            
            # Very basic heuristic to avoid HTML pages returning 200
            if "<html" in text[:500].lower() and "swagger" not in text[:500].lower():
                return url, None
                
            if "json" in content_type or text.strip().startswith("{"):
                try:
                    return url, json.loads(text)
                except json.JSONDecodeError:
                    pass
                
            if "yaml" in content_type or "openapi:" in text[:200] or "swagger:" in text[:200]:
                try:
                    return url, yaml.safe_load(text)
                except yaml.YAMLError:
                    pass
                
            # If Content-Type is missing but it looks like Swagger JSON
            if '"swagger":"' in text.replace(" ", "") or '"openapi":"' in text.replace(" ", ""):
                 try:
                     return url, json.loads(text)
                 except json.JSONDecodeError:
                     pass

        except (AttributeError, TypeError):
            pass
        return url, None

    def analyze_schema(self, schema_data: Dict[str, Any]) -> List[Dict]:
        """Parses the schema block to build actionable attack targets (endpoints and parameters)."""
        targets = []
        if not isinstance(schema_data, dict):
            return targets
            
        paths = schema_data.get("paths", {})
        base_path = schema_data.get("basePath", "")
        
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                    continue
                    
                full_path = f"{base_path.rstrip('/')}/{path.lstrip('/')}"
                parameters = details.get("parameters", [])
                
                # Extract interesting parameters for BOLA/Injection
                target_params = []
                for param in parameters:
                    if isinstance(param, dict):
                        p_name = param.get("name")
                        p_in = param.get("in", "query") # query, path, header, formData, body
                        p_type = param.get("type") or param.get("schema", {}).get("type", "string")
                        if p_name:
                            target_params.append({
                                "name": p_name,
                                "in": p_in,
                                "type": p_type,
                                "required": param.get("required", False)
                            })
                
                if target_params:
                     targets.append({
                         "path": full_path,
                         "method": method.upper(),
                         "params": target_params,
                         "summary": details.get("summary", "Unknown Operation")
                     })
                     
        console.print(f"[bold cyan][+] API Breaker: Successfully parsed {len(targets)} active endpoints from schema.[/bold cyan]")
        return targets

    async def synthesize_bola_attack(self, base_url: str, targets: List[Dict]) -> List[Dict]:
        """
        Synthesizes functional requests and mutates identifiers to find BOLA vulnerabilities.
        """
        findings = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        console.print(f"[bold red][💥] API Breaker: Synthesizing autonomous BOLA attacks on {len(targets)} endpoints...[/bold red]")
        
        for t in targets:
            method = t["method"]
            api_path = t["path"]
            params = t["params"]
            
            # Check if this endpoint has ID-like parameters indicating user/object isolation
            id_params = [p for p in params if any(kw in p["name"].lower() for kw in ["id", "user", "account", "uuid", "profile"])]
            
            if not id_params:
                continue # Skip endpoints without identity context for BOLA
                
            path = api_path
            query_str = "?"
            json_body = {}
            
            for p in params:
                val = self._generate_mock_value(p)
                if p["in"] == "path":
                    path = path.replace(f"{{{p['name']}}}", str(val))
                elif p["in"] == "query":
                    query_str += f"{p['name']}={val}&"
                elif p["in"] == "body":
                    json_body[p['name']] = val
                    
            full_url = urljoin(base, path)
            if query_str != "?":
                full_url += query_str.rstrip("&")
                
            # Perform a baseline request first
            try:
                base_resp = await self._send_attack(method, full_url, json_body)
                
                if base_resp and (200 <= base_resp.status_code < 300 or base_resp.status_code in [401, 403]):
                     # Mutate the ID and re-test
                     for id_p in id_params:
                         for mutant_id in self._get_mutant_ids(id_p["name"]):
                             m_path = api_path
                             m_query_str = "?"
                             m_json_body = json_body.copy()
                             
                             # Rebuild request with mutated ID
                             for p in params:
                                 val = mutant_id if p["name"] == id_p["name"] else self._generate_mock_value(p)
                                 if p["in"] == "path":
                                     m_path = m_path.replace(f"{{{p['name']}}}", str(val))
                                 elif p["in"] == "query":
                                     m_query_str += f"{p['name']}={val}&"
                                 elif p["in"] == "body":
                                     m_json_body[p['name']] = val
                                     
                             m_full_url = urljoin(base, m_path) + (m_query_str.rstrip("&") if m_query_str != "?" else "")
                             
                             m_resp = await self._send_attack(method, m_full_url, m_json_body)
                             
                             # BOLA Detection Heuristics
                             if m_resp and 200 <= m_resp.status_code < 300:
                                 # We accessed another ID successfully
                                 # (In a real scenario, we'd need to verify the response body actually changed and wasn't a generic 200)
                                 if base_resp.status_code in [401, 403] or len(m_resp.text) != len(base_resp.text):
                                     finding = {
                                         "type": "Broken Object Level Authorization (BOLA)",
                                         "content": f"[BOLA] Unauthenticated/Cross-tenant access allowed on `{method} {api_path}` via parameter `{id_p['name']}={mutant_id}`.",
                                         "evidence_url": m_full_url,
                                         "severity": "CRITICAL",
                                         "impact_desc": f"Attackers can iterate over the `{id_p['name']}` parameter to systematically scrape, modify, or delete other users' objects.",
                                         "remediation_fix": "Implement strict server-side authorization checks verifying the requesting user owns the requested object ID."
                                     }
                                     findings.append(finding)
                                     console.print(f"[bold red][[BOLA HIT]] Cross-tenant access allowed on: {m_full_url}[/bold red]")
                                     break # Move to next endpoint if we proved BOLA
            except Exception as e:
                pass
                
        return findings

    def _generate_mock_value(self, param: Dict) -> Any:
        p_name = param["name"].lower()
        p_type = param["type"]
        
        for key, vals in self.common_parameters.items():
            if key in p_name:
                return random.choice(vals)
                
        if p_type == "integer": return random.randint(1, 100)
        if p_type == "boolean": return True
        return "test_aura_string"

    def _get_mutant_ids(self, param_name: str) -> List[str]:
        p_name = param_name.lower()
        for key, vals in self.common_parameters.items():
            if key in p_name:
                # Return other IDs to test cross-tenant
                return [v for v in vals if v not in ["1", "admin", "test@example.com"]]
        return ["2", "3", "999"]
        
    async def _send_attack(self, method: str, url: str, json_body: dict):
        kwargs = {}
        if json_body and method in ["POST", "PUT", "PATCH"]:
            kwargs["json"] = json_body
        return await self.session.request(method, url, **kwargs)

    async def scan_target(self, target_url: str) -> List[Dict]:
        """Main entrypoint for API Breaker."""
        all_findings = []
        schemas = await self.probe_schemas(target_url)
        
        for schema in schemas:
            finding = {
                "type": "Information Disclosure",
                "content": f"Exposed API Schema Document found at: {schema['url']}",
                "severity": "MEDIUM",
                "evidence_url": schema["url"]
            }
            all_findings.append(finding)
            
            targets = self.analyze_schema(schema["data"])
            if targets:
                bola_findings = await self.synthesize_bola_attack(target_url, targets)
                all_findings.extend(bola_findings)
                
        return all_findings
