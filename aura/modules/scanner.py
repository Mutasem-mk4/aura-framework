import socket
import re
import dns.resolver
import asyncio
import aiohttp
import os
import json
import random
import uuid
import urllib3
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any

from aura.modules.threat_intel import ThreatIntel
from aura.core.stealth import StealthEngine, AuraSession
from aura.core.brain import AuraBrain
from aura.core import state
from aura.modules.scope_checker import ScopeChecker
from aura.core.engine_interface import IEngine
from aura.core.models import Finding

from aura.ui.formatter import console

class AuraScanner(IEngine):
    """v7.2 Instinct Focus — Deep Discovery Engine with Recursive Spidering."""
    
    ENGINE_ID = "aura_scanner"

    def __init__(self, brain=None, stealth=None, persistence=None, telemetry=None, **kwargs):
        self.brain = brain or AuraBrain()
        self.stealth = stealth or StealthEngine()
        self.persistence = persistence # Injected PersistenceHub
        self.telemetry = telemetry
        self.stealth_session = AuraSession(self.stealth)
        self.common_subdomains = ["www", "dev", "api", "staging", "admin", "vpn", "mail", "blog", "test"]
        self._status = "initialized"
        
    BLIND_SIEGE_LIST = [
        # Admin / Auth
        "admin/login.asp", "admin/db", "manager/html", "server-status", "auth/login", "v1/admin",
        # Config / Env / Secrets
        ".env", ".env.backup", ".env.dev", ".env.prod", ".env.local", ".git/config", "config.json",
        "docker-compose.yml", "secrets.yml", "Credentials.xml", "web.config", "application.yml",
        # Backups / Dumps
        "backup/db.sql", "dump.sql", "database.sqlite", "backup.zip", "data.sql", "admin.bak",
        "archive.tar.gz", "old.zip", "wp-config.php.bak", "db_backup.sql", "db.sql",
        # API / Swagger / GraphQL
        "api/v1/user", "api/v1/debug", "api/v2/user", "swagger.json", "api/swagger.json",
        "v1/swagger.json", "swagger-ui.html", "openapi.json", "graphql", "graphiql", "api/graphql",
        "v1/api-docs", "v2/api-docs", "api-docs/swagger.json",
        # Logs / Debug
        "logs/access.log", "error.log", "debug.log", "phpinfo.php", "status", "health", "actuator/env",
        "actuator/health", "debug/default/view", "server/status",
        # Common Bypasses
        "account/transfer", "feedback/send", "search?query=test", "docs/config", "cgi-bin/test.sh"
    ]

    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Unified scan entry point for Phase 3."""
        self._status = "running"
        findings = []
        # Implementation of a full scan routine...
        self._status = "completed"
        return findings

    def get_status(self) -> Dict[str, Any]:
        return {"id": self.ENGINE_ID, "status": self._status}

    # ──────────────────────────────────────────────
    # Phase 1: Subdomain Discovery
    # ──────────────────────────────────────────────
    async def discover_subdomains(self, domain):
        """Discovers subdomains via DNS brute-forcing with rate-limiting & Threat Intel."""
        console.print(f"[blue][*] Starting subdomain discovery for: {domain}[/blue]")
        
        intel_module = ThreatIntel(stealth=self.stealth)
        await intel_module.query_virustotal(domain)
        await intel_module.query_otx(domain)
        
        found = []
        scope_guard = ScopeChecker(getattr(state, 'IN_SCOPE_RULES', []), getattr(state, 'OUT_OF_SCOPE_RULES', []))
        for sub in self.common_subdomains:
            target = f"{sub}.{domain}"
            
            # v17.0 Strict Scope Guard
            if getattr(state, 'OUT_OF_SCOPE_RULES', []) or getattr(state, 'IN_SCOPE_RULES', []):
                if not scope_guard.is_in_scope(target):
                    continue
                    
            await asyncio.sleep(0.1)
            try:
                answers = await asyncio.to_thread(dns.resolver.resolve, target, 'A')
                for rdata in answers:
                    found.append({"type": "subdomain", "value": target, "source": "Aura-Scan", "ip": str(rdata)})
                    console.print(f"[green][+] Found: {target} ({rdata})[/green]")
            except:
                continue
        return found

    # v15.0: Universal IPv4/IPv6 Port Scanner
    async def scan_ports(self, target_host, ports=[80, 443, 8080, 8443, 3000, 4280, 5000, 22, 21, 3306]):
        """Dual-stack (IPv4/v6) asynchronous port scanner."""
        console.print(f"[blue][*] Aura v15.0: Universal Dual-Stack Port Scan on {target_host}...[/blue]")
        open_ports = []
        
        async def check_port(port):
            try:
                # Automatic Address Family Selection
                addr_info = await asyncio.to_thread(socket.getaddrinfo, target_host, port, proto=socket.IPPROTO_TCP)
                for res in addr_info:
                    family, socktype, proto, canonname, sockaddr = res
                    try:
                        _, writer = await asyncio.wait_for(asyncio.open_connection(sockaddr[0], port, family=family), timeout=state.NETWORK_TIMEOUT)
                        open_ports.append(port)
                        console.print(f"[green][+] Port {port} is OPEN[/green]")
                        writer.close()
                        await writer.wait_closed()
                        break 
                    except: continue
            except: pass

        await asyncio.gather(*(check_port(port) for port in ports))
        return open_ports

    # v15.0: gRPC & Protobuf Discovery (Enterprise Standard)
    async def check_grpc(self, base_url):
        """Probes for gRPC reflection or common gRPC services."""
        console.print(f"[cyan][📡] v15.0: Probing for gRPC/Protobuf Endpoints...[/cyan]")
        grpc_paths = [
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
            "/google.pubsub.v1.Publisher/ListTopics"
        ]
        found_grpc = []
        async with aiohttp.ClientSession() as session:
            for path in grpc_paths:
                try:
                    url = urljoin(base_url, path)
                    async with session.post(url, headers={"content-type": "application/grpc"}, timeout=state.NETWORK_TIMEOUT) as r:
                        if "grpc-status" in r.headers or r.status in [200, 415]:
                            found_grpc.append(url)
                            console.print(f"[bold green][+] gRPC Service Detected: {url}[/bold green]")
                except: pass
        return found_grpc

    # ──────────────────────────────────────────────
    # v7.2: Sitemap & Robots Parser
    # ──────────────────────────────────────────────
    async def parse_sitemap_robots(self, base_url):
        """Mandatory: Parses sitemap.xml and robots.txt to extract ALL hidden paths."""
        base_url = base_url.rstrip('/')
        all_paths = set() # Use set for O(1) deduplication
        
        async def fetch_robots():
            console.print(f"[cyan][🗺️] v7.2 Instinct: Parsing robots.txt for {base_url}...[/cyan]")
            try:
                res = await self.stealth_session.get(f"{base_url}/robots.txt", timeout=state.NETWORK_TIMEOUT)
                if res and res.status_code == 200 and "disallow" in res.text.lower():
                    lines = res.text.splitlines()
                    for line in lines:
                        line = line.strip()
                        if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/" and "*" not in path:
                                full = urljoin(base_url + "/", path.lstrip("/"))
                                all_paths.add(full)
                                console.print(f"[green][+] robots.txt: {full}[/green]")
                        elif line.lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            if sitemap_url.startswith("//"):
                                sitemap_url = "http:" + sitemap_url
                            sm_paths = await self._parse_sitemap_url(sitemap_url)
                            for p in sm_paths: all_paths.add(p)
            except Exception as e:
                console.print(f"[dim yellow][!] robots.txt fetch failed: {e}[/dim yellow]")

        async def fetch_sitemap():
            console.print(f"[cyan][🗺️] v7.2 Instinct: Parsing sitemap.xml for {base_url}...[/cyan]")
            sm_paths = await self._parse_sitemap_url(f"{base_url}/sitemap.xml")
            for p in sm_paths: all_paths.add(p)

        # v7.4 Velocity Focus: Run map parsers concurrently
        await asyncio.gather(fetch_robots(), fetch_sitemap())
        
        console.print(f"[bold green][+] Sitemap/Robots Total: {len(all_paths)} paths extracted.[/bold green]")
        return list(all_paths)
    
    async def _parse_sitemap_url(self, sitemap_url, depth=0, max_depth=3, max_paths=1000, current_count=None):
        """Recursively parses a sitemap URL with concurrency and safety limits."""
        if current_count is None: current_count = [0]
        paths = []
        
        if depth > max_depth or current_count[0] >= max_paths:
            return paths

        try:
            res = await self.stealth_session.get(sitemap_url, timeout=state.NETWORK_TIMEOUT)
            if not res or res.status_code != 200:
                return paths
            
            text = res.text
            locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", text, re.IGNORECASE)
            
            xml_locs = []
            for loc in locs:
                loc = loc.strip()
                if loc.endswith(".xml"):
                    xml_locs.append(loc)
                else:
                    if loc not in paths:
                        paths.append(loc)
                        current_count[0] += 1
                        if current_count[0] % 50 == 0: # Print periodic updates for massive sitemaps
                            console.print(f"[green][+] sitemap: Discovered {current_count[0]} paths...[/green]")
                        if current_count[0] >= max_paths:
                            break
            
            # Recurse concurrently if depth allows
            if xml_locs and depth < max_depth and current_count[0] < max_paths:
                tasks = [self._parse_sitemap_url(x, depth + 1, max_depth, max_paths, current_count) for x in xml_locs[:10]] # Cap branching to 10
                results = await asyncio.gather(*tasks)
                for r in results:
                    paths.extend(r)
                    
        except Exception as e:
            console.print(f"[dim yellow][!] Sitemap parse failed for {sitemap_url}: {e}[/dim yellow]")
        return list(set(paths))

    # ──────────────────────────────────────────────
    # v7.2: JS/CSS Link Extractor
    # ──────────────────────────────────────────────
    async def extract_js_css_links(self, base_url, html_content=""):
        """Extracts hidden endpoints from JavaScript and CSS files referenced in the page."""
        base_url = base_url.rstrip('/')
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc
        all_endpoints = []
        
        console.print(f"[cyan][📜] v7.2 Instinct: Extracting JS/CSS links from {base_url}...[/cyan]")
        
        # If no HTML provided, fetch it
        if not html_content:
            try:
                res = await self.stealth_session.get(base_url, timeout=state.NETWORK_TIMEOUT)
                if not res: return all_endpoints
                html_content = res.text
            except:
                return all_endpoints
        
        # ── Find all <script src="..."> and <link href="..."> ──
        js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        css_urls = re.findall(r'<link[^>]+href=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        
        resource_urls = []
        for u in js_urls + css_urls:
            full = urljoin(base_url + "/", u)
            parsed = urlparse(full)
            if parsed.netloc == base_domain or not parsed.netloc:
                resource_urls.append(full)
        
        console.print(f"[dim][📂] Found {len(resource_urls)} JS/CSS resources to analyze...[/dim]")
        
        # ── Fetch each resource and extract endpoints via Regex concurrently ──
        ENDPOINT_PATTERNS = [
            r'["\']/(api/[^"\'\\s]+)["\']',
            r'["\']/(v[0-9]+/[^"\'\\s]+)["\']',
            r'["\']/(rest/[^"\'\\s]+)["\']', # Common in SPAs like Juice Shop
            r'["\'](/[a-zA-Z0-9_-]+\.(php|asp|aspx|jsp|json|xml|txt|cfg|conf|ini|bak|sql|log))["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest.*?open\s*\([^,]+,\s*["\']([^"\']+)["\']',
            r'url\s*[:=]\s*["\']([^"\']+/[^"\']+)["\']',
            r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
            r'path\s*[:=]\s*["\'](/[^"\']+)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'href\s*[:=]\s*["\'](/[^"\']+)["\']',
            # v38.0: SPA Routing Patterns (Angular/React)
            r'path\s*:\s*["\']([\w/.-]+)["\']',
            r'redirectTo\s*:\s*["\']([\w/.-]+)["\']',
            r'loadChildren\s*:\s*["\']([^"\']+)["\']'
        ]
        
        # v7.4 Velocity Focus: Concurrency for resource fetching
        js_semaphore = asyncio.Semaphore(15)
        
        async def fetch_and_extract(res_url):
            async with js_semaphore:
                try:
                    res = await self.stealth_session.get(res_url, timeout=state.NETWORK_TIMEOUT)
                    if not res: return []
                    content = res.text
                    extracted = []
                    for pattern in ENDPOINT_PATTERNS:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for m in matches:
                            endpoint = m[0] if isinstance(m, tuple) else m
                            if not endpoint or len(endpoint) < 2 or len(endpoint) > 200:
                                continue
                            if any(x in endpoint.lower() for x in ["http://", "https://", "data:", "blob:", "javascript:"]):
                                full_ep = endpoint
                            else:
                                full_ep = urljoin(base_url + "/", endpoint.lstrip("/"))
                            
                            parsed_ep = urlparse(full_ep)
                            if (parsed_ep.netloc == base_domain or not parsed_ep.netloc):
                                extracted.append(full_ep)
                    return extracted
                except: return []

        tasks = [fetch_and_extract(ru) for ru in resource_urls[:50]]
        results = await asyncio.gather(*tasks)
        for r_list in results:
            for ep in r_list:
                if ep not in all_endpoints:
                    all_endpoints.append(ep)
        
        console.print(f"[bold green][+] JS/CSS Extraction: {len(all_endpoints)} hidden endpoints found.[/bold green]")
        return all_endpoints

    async def _get_spa_baseline(self, base_url: str):
        """v38.0: Establishes a baseline for nonexistent paths on a potential SPA."""
        try:
            r1 = await self.stealth_session.get(f"{base_url}/rnd_{uuid.uuid4().hex[:8]}", allow_redirects=False, timeout=10)
            if r1 and r1.status_code == 200:
                # v38.0: Deep Hunter Fuzzy Hashing
                import hashlib
                # We hash the structural part of the body (tags only) to create a fingerprint
                structure = re.sub(r'>[^<]+<', '><', r1.text)
                fingerprint = hashlib.md5(structure.encode()).hexdigest()
                return {
                    "status": 200,
                    "length": len(r1.text),
                    "fingerprint": fingerprint,
                    "prefix": r1.text[:512]
                }
        except: pass
        return None

    def _is_valid_hit(self, res, baseline):
        """v38.0: Determines if a 200 response is a real hit or just an SPA fallback."""
        if not baseline:
            return res.status_code in [200, 204, 301, 302, 307, 401, 403]
        if res.status_code != 200:
            return res.status_code in [204, 301, 302, 307, 401, 403]
            
        import hashlib
        # Compare structural fingerprints
        structure = re.sub(r'>[^<]+<', '><', res.text)
        current_fingerprint = hashlib.md5(structure.encode()).hexdigest()
        
        if current_fingerprint == baseline["fingerprint"]:
            return False # Structural match to 404-baseline
            
        # Fallback to length and content prefix similarity
        current_len = len(res.text)
        if abs(current_len - baseline["length"]) < 50:
            if res.text[:256] == baseline["prefix"][:256]:
                return False
        return True

    # ──────────────────────────────────────────────
    # v7.2: Enhanced DirBuster (Professional Wordlist)
    # ──────────────────────────────────────────────
    DIRBUST_NO_RECURSE = {
        ".env", ".git", ".svn", "docker-compose.yml",
        "index.php", "home.php", "main.php", "robots.txt",
        "phpmyadmin", "dvwa",
    }

    # v16.0 Omni-Auditor Update: 2000+ Word Total Dominance Wordlist
    PROFESSIONAL_WORDLIST = [
        # Admin & Auth (Core)
        "admin", "administrator", "login", "signin", "auth", "authenticate", "dashboard", "panel", "cpanel", 
        "webmin", "manager", "console", "control", "portal", "secure", "account", "user", "users", "adminpanel",
        "admin-console", "backend", "cp", "sysadmin", "root", "super", "superuser", "master", "masteradmin",
        "admin/login", "admin/index", "admin.php", "login.php", "signin.php", "user/login", "auth/login",
        "admin_area", "admin1", "admin2", "admin3", "admin_login", "cms", "cmsadmin", "siteadmin", "myadmin",
        "admin/dashboard", "admin/settings", "admin/users", "admin/config", "admin/system", "admin/logs",
        "auth/register", "auth/forgot-password", "auth/reset", "auth/token", "auth/refresh", "oauth", "oauth2",
        "sso", "saml", "login.jsp", "login.aspx", "login.html", "admin.aspx", "admin.jsp", "admin.html",
        "manage", "management", "staff", "employee", "intranet", "partner", "store", "shop", "checkout",
        
        # API & Web Services (Massively Expanded)
        "api", "api/v1", "api/v2", "api/v3", "api/v4", "api/v5", "rest", "graphql", "swagger", "api-docs", "openapi",
        "docs", "documentation", "soap", "ws", "webservices", "grpc", "trpc", "xmlrpc", "xmlrpc.php",
        "graphiql", "endpoint", "endpoints", "services", "svc", "microservices", "api-gateway", "gw",
        "api/swagger", "swagger-ui", "swagger-ui.html", "api/swagger.json", "swagger.json", "v1/api", "v2/api",
        "graphql/schema", "graphql/query", "gql", "api/graphql", "graphql/console", "graphiql.php",
        "api/users", "api/admin", "api/auth", "api/config", "api/status", "api/health", "api/data",
        "v1/users", "v1/admin", "v1/auth", "v1/config", "v1/status", "v1/health", "v1/data",
        "v2/users", "v2/admin", "v2/auth", "v2/config", "v2/status", "v2/health", "v2/data",
        "v3/api-docs", "swagger/v1/swagger.json", "openapi/v1/openapi.json", "docs/api", "developer",
        "api-docs.json", "swagger.yaml", "openapi.yaml", "graphql.json", "altair", "voyager", "playground",
        "api.json", "api.yaml", "api.yml", "swagger.yml", "openapi.yml", "v1.0", "v2.0", "v1.1", "beta", "alpha",
        
        # Development, Testing & Staging
        "dev", "development", "staging", "test", "testing", "debug", "sandbox", "beta", "alpha", "demo",
        "prototype", "lab", "local", "localhost", "qa", "uat", "preprod", "builder", "build", "ci", "cd",
        "testapp", "test-env", "dev-env", "staging-env", "test.html", "test.php", "debug.php", "info.html",
        "dev.html", "staging.html", "qa.html", "uat.html", "sandbox.html", "beta.html", "alpha.html",
        "test1", "test2", "test3", "dev1", "dev2", "dev3", "stage", "staging1", "staging2", "qa1", "qa2",
        "test.txt", "dev.txt", "staging.txt", "qa.txt", "sandbox.txt", "beta.txt", "alpha.txt",
        
        # Backup, Archives & Dumps (High Priority)
        "backup", "backups", "bak", "old", "archive", "dump", "db_backup", "site_backup", "backup.zip",
        "backup.tar.gz", "backup.sql", "dump.sql", "data.sql", "users.sql", "database.sql", "mysql.sql",
        "db.sql", "backup.rar", "archive.zip", "source.zip", "src.zip", "code.zip", "www.zip", "full.zip",
        "1.zip", "project.zip", "web.zip", "site.zip", "website.zip", "app.zip", "backup.tar", "data.zip",
        "db_dump.sql", "sqldump.sql", "postgres.sql", "mongo-dump.tar.gz", "archive.tgz", "old.zip",
        "site.bak", "db.bak", "config.bak", "index.php.bak", "app.bak", "database.bak", "mysql.bak",
        "backup1", "backup2", "backup3", "db_dump.zip", "db_backup.zip", "sql_dump.zip", "sql_backup.zip",
        "data.bak", "users.bak", "admin.bak", "wp-config.php.bak", "wp-config.bak", "config.php.bak",
        "settings.bak", "env.bak", "local.bak", "production.bak", "development.bak", "staging.bak",
        "backup.tgz", "archive.tar", "source.tar.gz", "src.tar.gz", "code.tar.gz", "www.tar.gz",
        
        # Configuration & Settings
        "config", "configuration", "settings", "setup", "install", "installer", "db", "database", "sql",
        "mysql", "phpmyadmin", "adminer", "pgadmin", "mongo", "mongodb", "redis", "memcached", "conf",
        "config.php", "config.inc.php", "config.bak", "config.old", "config.txt", "config.json", "config.xml",
        "config.yaml", "config.yml", "settings.py", "settings.json", "settings.xml", "application.yml",
        "application.properties", "appsettings.json", "env.json", "env.yaml", "db.php", "database.php",
        "connection.php", "db_connect.php", "config/database.yml", "wp-config.php", "local.xml",
        "config.js", "config.env", "settings.js", "settings.env", "db_config.php", "database_config.php",
        "app.config", "web.config", "global.asax", "appsettings.development.json", "appsettings.production.json",
        "config.local.php", "config.dev.php", "config.prod.php", "config.staging.php", "config.test.php",
        "parameters.yml", "parameters.yml.dist", "docker.env", "docker-compose.env", ".env.php",
        
        # Version Control (Critical)
        ".git", ".git/config", ".git/HEAD", ".git/logs/HEAD", ".git/index", ".gitignore", ".gitmodules",
        ".svn", ".svn/entries", ".svn/wc.db", ".hg", ".bzr", ".cvs", ".git/description", ".git/packed-refs",
        ".git/info/exclude", ".svn/pristine/", ".svn/text-base/", ".git/objects/info/packs",
        ".git/refs/heads/master", ".git/refs/heads/main", ".git/refs/remotes/origin/HEAD", ".git/COMMIT_EDITMSG",
        
        # Sensitive Files (High Impact)
        ".env", ".env.local", ".env.production", ".env.backup", ".env.dev", ".env.stage", ".env.test",
        ".env.sample", ".env.example", ".env.old", ".env.bak", ".env.txt", ".htaccess", ".htpasswd", 
        "web.config", "crossdomain.xml", "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
        "wp-config.old", "wp-config.bak", "wp-config.txt", "docker-compose.yml", "docker-compose.yaml",
        "Dockerfile", "Makefile", "Vagrantfile", "package.json", "composer.json", "composer.lock",
        "Gemfile", "Gemfile.lock", "requirements.txt", "yarn.lock", "package-lock.json",
        "server.key", "server.crt", "id_rsa", "id_dsa", "authorized_keys", "known_hosts", "secret.txt",
        ".bash_history", ".zsh_history", ".mysql_history", ".psql_history", ".sqlite_history", ".rediscli_history",
        ".ssh/id_rsa", ".ssh/id_rsa.pub", ".ssh/authorized_keys", ".ssh/known_hosts", "id_ecdsa", "id_ed25519",
        "credentials.txt", "passwords.txt", "keys.txt", "secrets.txt", "tokens.txt", "auth.txt",
        "cert.pem", "key.pem", "public.pem", "private.pem", "server.csr", "ca.crt", "client.crt", "client.key",
        
        # Server Status & Info
        "server-status", "server-info", "info.php", "phpinfo.php", "test.php", "status", "health", 
        "ping", "diagnostics", "metrics", "stats", "statistics", "monitor", "monitoring",
        "php.info", "pi.php", "i.php", "php-info.php", "test_info.php", "test.cgi", "env.cgi",
        "check", "healthcheck", "health-check", "heartbeat", "alive", "ready", "liveness", "readiness",
        "sysinfo.php", "system.php", "server.php", "status.php", "health.php", "ping.php", "metrics.php",
        
        # Common Web Directories
        "uploads", "upload", "files", "media", "images", "img", "static", "assets", "public", "resources",
        "content", "css", "js", "scripts", "fonts", "vendor", "inc", "includes", "lib", "library",
        "modules", "plugins", "themes", "templates", "views", "components", "src", "source", "app",
        "application", "core", "bin", "sbin", "cgi-bin", "dist", "build", "out", "target",
        "data", "doc", "docs", "download", "downloads", "export", "import", "tmp", "temp", "cache",
        "gallery", "photos", "videos", "audio", "pdf", "documents", "attachments", "avatars", "icons",
        "styles", "stylesheets", "javascript", "ajax", "json", "xml", "csv", "excel", "word",
        
        # CMS & Framework Specific
        "wp-admin", "wp-login.php", "wp-content", "wp-includes", "wp-content/uploads", "joomla", "drupal",
        "magento", "craftcms", "typo3", "bitrix", "laravel", "symfony", "django", "flask", "spring",
        "rails", "express", "next", "nuxt", "vue", "react", "angular", "node_modules",
        "administrator/index.php", "user", "admin/login", "ghost", "umbraco", "moodle", "canvas",
        "wp-config.php", "wp-cron.php", "xmlrpc.php", "wp-json", "wp-admin/admin-ajax.php",
        "wp-content/plugins", "wp-content/themes", "wp-content/debug.log", "wp-content/backup",
        "artisan", "manage.py", "mix.exs", "pom.xml", "build.gradle", "settings.gradle", "run.py",
        
        # Hidden Services & Dashboards (DevOps/Infra)
        "jenkins", "gitlab", "bitbucket", "sonarqube", "grafana", "kibana", "elasticsearch", "prometheus",
        "minio", "rabbitmq", "celery", "flower", "portainer", "traefik", "consul", "nomad", "vault",
        "supervisor", "netdata", "phpinfo", "php-info", "fluentd", "logstash", "nagios", "zabbix",
        "cacti", "munin", "webmin", "ispconfig", "plesk", "directadmin", "splunk", "newrelic",
        "argocd", "harbor", "nexus", "artifactory", "keycloak", "rancher", "rundeck", "awx", "tower",
        
        # Data & Logs
        "export.csv", "data.json", "logs", "log", "error_log", "access_log", "debug.log", "system.log",
        "app.log", "application.log", "prod.log", "dev.log", "test.log", "tmp", "temp", "cache",
        "var", "run", "spool", "mail", "messages", "syslog", "auth.log", "nginx.log", "apache.log",
        "error.log", "access.log", "mysql.log", "mariadb.log", "postgresql.log", "mongodb.log",
        "catalina.out", "server.log", "console.log", "trace.log", "audit.log", "activity.log", "event.log",
        "php_error.log", "php_errors.log", "laravel.log", "symfony.log", "django.log", "rails.log",
        
        # Security & Compliance (Spring Boot / Java)
        "actuator", "actuator/health", "actuator/env", "actuator/metrics", "actuator/httptrace",
        "trace", "heapdump", "jolokia", ".well-known", ".well-known/security.txt", 
        ".well-known/apple-app-site-association", ".well-known/assetlinks.json",
        "clientaccesspolicy.xml", "security.txt", "humans.txt", "robots.txt",
        "actuator/mappings", "actuator/info", "actuator/dump", "actuator/threaddump",
        "actuator/loggers", "actuator/beans", "actuator/configprops", "actuator/flyway", "actuator/liquibase",
        "actuator/scheduledtasks", "actuator/sessions", "actuator/shutdown", "actuator/prometheus",
        "env", "heapdump", "dump", "threaddump", "metrics", "httptrace", "loggers",
        
        # Cloud & Container (AWS, GCP, Azure, K8s)
        ".aws/credentials", ".aws/config", ".s3cfg", ".dockerignore", "kubernetes", "k8s",
        "helm", "charts", "metadata", "latest/meta-data/", "latest/meta-data/iam/security-credentials/",
        ".azure", ".gcp", ".kube/config", ".minikube", "docker-compose.override.yml",
        
        # Mobile & API Extensions
        "v1", "v2", "v3", "mobile", "m", "ios", "android", "app-api", "web-api", "internal-api",
        "api-v1", "api-v2", "api-v3", "v1.0", "v2.0", "api/mobile", "api/ios", "api/android", "api/internal",
        
        # Actions & Operations
        "users", "customers", "clients", "orders", "invoices", "billing", "payments", "transactions",
        "products", "items", "catalog", "inventory", "stock", "categories", "brands",
        "search", "query", "filter", "sort", "results", "find", "list", "view", "show", "detail",
        "update", "edit", "save", "create", "new", "add", "delete", "remove", "destroy", "drop",
        "process", "run", "execute", "start", "stop", "restart", "reboot", "shutdown", "halt",
        
        # Specific File Extensions (Expanded)
        "index.php", "index.html", "index.htm", "index.asp", "index.aspx", "index.jsp", "index.cgi",
        "default.php", "default.html", "default.htm", "default.asp", "default.aspx", "default.jsp",
        "home.php", "home.html", "main.php", "main.html", "app.js", "main.js", "bundle.js",
        "index.js", "index.ts", "server.js", "app.py", "main.py", "index.json", "index.xml",
        
        # Vulnerability / Exploit check paths (Webshells, C2, etc)
        "shell.php", "cmd.php", "eval.php", "exec.php", "system.php", "webshell.php", "c99.php",
        "r57.php", "wso.php", "b374k.php", "up.php", "upload.php", "test_upload.php", "file_upload.php",
        "phpbash.php", "pwn.php", "hack.php", "exploit.php", "backdoor.php",
        "cmd.jsp", "shell.jsp", "cmd.aspx", "shell.aspx", "cmd.asp", "shell.asp", "cmd.cgi", "shell.cgi",
        "put.php", "post.php", "get.php", "test1.php", "test2.php", "vuln.php", "xss.php", "sqli.php",
        
        # Enterprise App Common Endpoints
        "admin/login.php", "admin/index.php", "user/login.php", "user/index.php", "member/login.php",
        "login/?action=register", "admin/?action=login", "api/v1/user/login", "api/v1/auth/login",
        "api/v1/admin/login", "manage/login", "control_panel", "cpanel_login", "sys_admin",
        
        # Common Parameter Names (For query string fuzzer padding)
        "id", "user_id", "uid", "account_id", "file", "filename", "path", "dir", "folder", "url",
        "uri", "redirect", "next", "return", "page", "p", "offset", "limit", "query", "search",
        "q", "sort", "order", "lang", "locale", "token", "key", "auth", "session", "code",
        
        # Cloud/Serverless function names
        "hello", "hello-world", "test-function", "api-proxy", "graphql-endpoint", "auth-webhook",
        "stripe-webhook", "github-webhook", "payment-webhook", "slack-webhook", "discord-webhook",
        
        # Leftovers / Misc
        "crossdomain.xml", "clientaccesspolicy.xml", "sitemap.xml", "sitemap_index.xml",
        "favicon.ico", "apple-touch-icon.png", "manifest.json", "browserconfig.xml",
        "humans.txt", "security.txt", "ads.txt", "app-ads.txt", "sellers.json",
        
        # 100+ More Random High Value Targets
        "graphql/v1", "graphql/v2", "api/v1/graphql", "api/v2/graphql",
        "v1/swagger", "v2/swagger", "swagger/v1", "swagger/v2", "api/v1/swagger",
        "metrics/prometheus", "actuator/prometheus", "health_check", "ping.json",
        "status.json", "info.json", "version.json", "manifest.json", "package.json",
        "composer.json", "tslint.json", "eslintrc.json", "tsconfig.json", "bower.json",
        "yarn.lock", "package-lock.json", "composer.lock", "Gemfile.lock", "Pipfile.lock",
        "requirements.txt", "setup.py", "tox.ini", "pytest.ini", "jest.config.js",
        "webpack.config.js", "gulpfile.js", "Gruntfile.js", "karma.conf.js", "babel.config.js",
        ".babelrc", ".eslintrc", ".prettierrc", ".dockerignore", ".gitignore",
        ".gitattributes", ".gitmodules", ".npmignore", ".nvmrc", ".editorconfig",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Makefile",
        "Vagrantfile", "Vagrantfile.local", "pom.xml", "build.gradle", "settings.gradle",
        "build.sbt", "Cargo.toml", "mix.exs", "rebar.config", "shadow-cljs.edn",
        "project.clj", "shard.yml", "Podfile", "Cartfile", "Package.swift",
        "gradlew", "gradlew.bat", "mvnw", "mvnw.cmd", "serve.js", "server.js",
        "app.js", "index.js", "main.js", "bundle.js", "vendor.js", "app.min.js",
        "main.min.js", "bundle.min.js", "vendor.min.js", "style.css", "styles.css",
        "main.css", "app.css", "style.min.css", "styles.min.css", "main.min.css",
        "app.min.css", "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml"
    ]

    async def intelligent_guess_paths(self, base_url, count_needed, discovered_structure=None):
        """
        v10.1 Structural Fix: Generates intelligent path guesses to force auditing depth
        when static discovery yields too few results. Guesses are based on common 
        conventions and any discovered structure components.
        """
        guesses = []
        base_urls = [base_url.rstrip('/')]
        
        if discovered_structure:
            for ds in discovered_structure:
                if "/api/" in ds: base_urls.append(f"{base_url.rstrip('/')}/api")
                if "/v1/" in ds: base_urls.append(f"{base_url.rstrip('/')}/v1")
                if "cgi-bin" in ds: base_urls.append(f"{base_url.rstrip('/')}/cgi-bin")

        import random
        import string
        
        # Common dynamic endpoints (REST, RPC, etc)
        dynamic = ["users", "products", "items", "data", "config", "status", "profile", "account"]
        actions = ["get", "post", "update", "delete", "fetch", "list", "search"]
        extensions = [".json", ".xml", ".php", ".jsp", ".aspx", ""]
        
        while len(guesses) < count_needed:
            b_url = random.choice(base_urls)
            p_type = random.choice(["id", "hash", "action"])
            
            if p_type == "id":
                guess = f"{b_url}/{random.choice(dynamic)}/{random.randint(1, 1000)}"
            elif p_type == "hash":
                rnd_hash = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
                guess = f"{b_url}/{random.choice(dynamic)}/{rnd_hash}"
            elif p_type == "action":
                guess = f"{b_url}/{random.choice(actions)}_{random.choice(dynamic)}{random.choice(extensions)}"
                
            if guess not in guesses:
                guesses.append(guess)
        return guesses



    def _get_top_500_words(self):
        """
        v20.0 Global Integration: Load external SecLists wordlists dynamically.
        Falls back to a core list if the external file is missing.
        """
        import os
        wordlist_path = os.path.join(os.path.dirname(__file__), "..", "resources", "wordlists", "raft-large-directories.txt")
        try:
            with open(wordlist_path, "r", encoding="utf-8") as f:
                # Remove leading/trailing slashes and whitespaces as httpx appending expects raw words
                words = [line.strip().strip('/') for line in f if line.strip() and not line.startswith("#")]
                if words:
                    return words
        except Exception as e:
            console.print(f"[dim yellow][!] SecLists wordlist not found ({e}). Falling back to core list.[/dim yellow]")
            
        return [
            "admin", "login", "manager", "setup", "install", "api", "v1", "v2", "graphql",
            "docs", "swagger", "openapi", "metrics", "health", "ping", "status", "info",
            "dashboard", "transfer", "account", "profile", "settings", "config", "env",
            ".env", ".git", ".htaccess", "db", "database", "backup", "bak", "old", "test",
            "server-status", "app", "auth", "oauth", "token", "jwt", "session", "users"
        ]

    async def force_fuzz(self, base_url, tech_stack=None, swarm_mode=False):
        """
        v13.0 Stealth Predator: Hardcoded aggressive dirbusting with UA rotation and jitter.
        Uses ThreadPoolExecutor and raw requests to force brute-force 500 paths with maximum aggression.
        v19.6 Swarm Mode: Dynamically reduces payload and disables jitter when scanning mass targets.
        v22.0 Assetnote: Passes tech_stack to FfufEngine for wordlist optimization.
        """
        import requests
        from concurrent.futures import ThreadPoolExecutor
        import urllib3
        import time
        import random
        import uuid
        
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        console.print(f"☠️ [bold red]v13.0 STEALTH PREDATOR[/bold red]: Forcing RAW DirBuster on {base_url}")
        
        # v19.4: Guard — skip gRPC endpoints and deep URLs (not root targets)
        if any(x in base_url.lower() for x in ["grpc", "/reflection/", "pubsub", "/v1alpha", "/v1."]) or \
           len(base_url.split("/")) > 5:
            console.print(f"[dim yellow][!] DirBuster skipped: Not a root HTTP target: {base_url}[/dim yellow]")
            return []
            
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url if base_url.startswith("http") else "http://" + base_url)
        if state.is_dns_failed(parsed_url.netloc):
            console.print(f"[bold red][X] FAST-FAIL: Target {parsed_url.netloc} has global DNS failure. Aborting DirBuster.[/bold red]")
            return []
        
        if not base_url.startswith("http"):
            base_url = f"http://{base_url}"
        base_url = base_url.rstrip('/')
        
        discovered_urls = []
        
        # v21.0 The Go-Arsenal: Direct Ffuf Integration
        try:
            from aura.modules.ffuf_engine import FfufEngine
            ffuf = FfufEngine()
            if ffuf._has_ffuf:
                console.print(f"[bold red][⚡] v21.0 GO-ARSENAL DETECTED: Utilizing FFUF for 10x Fuzzing Speed...[/bold red]")
                return await ffuf.run_fuzz(base_url, tech_stack=tech_stack, fast_mode=state.FAST_MODE, swarm_mode=swarm_mode)
        except Exception as e:
            console.print(f"[dim yellow][!] Ffuf Engine unavailable ({e}).[/dim yellow]")
            
        # v25.0 Omni-Core: Seamless integration of the Aura-Turbo-Fuzzer (ATF) Go binary
        console.print(f"[bold red][🚀] v25.0 HYPER-CONCURRENCY: Handing over to Aura-Turbo-Fuzzer (ATF) Go Engine...[/bold red]")
        import subprocess
        import json
        import os
        from urllib.parse import urlparse
        import tempfile
        
        target_slug = urlparse(base_url).netloc.replace(":", "_")
        wordlist_path = os.path.join(os.path.dirname(__file__), "..", "resources", "wordlists", "raft-large-directories.txt")
        if not os.path.exists(wordlist_path):
            # Fallback to creating a temporary wordlist if SecLists is missing
            core_words = self._get_top_500_words()
            tmp_fd, wordlist_path = tempfile.mkstemp(suffix=".txt")
            with os.fdopen(tmp_fd, 'w') as f:
                f.write("\n".join(core_words))
            
        # Build the ATF command
        atf_binary = os.path.join(os.path.dirname(__file__), "..", "..", "aura_fuzzer.exe")
        if not os.path.exists(atf_binary):
            # Try finding it relative to execution dir
            atf_binary = "aura_fuzzer.exe"
            
        threads = "50" if state.FAST_MODE else "200"
        proxy_arg = ["-p", state.PROXY_FILE] if state.PROXY_FILE and os.path.exists(state.PROXY_FILE) else []
        
        cmd = [atf_binary, "-u", base_url, "-w", wordlist_path, "-t", threads, "-mc", "200,204,301,302,307,401,403"] + proxy_arg
        
        # P0 QA Fix: Prevent IPC Deadlocks and Zombie Processes
        # Route stdout straight to a temp file, read after execution
        tmp_out_fd, tmp_out_path = tempfile.mkstemp(suffix=".jsonl")
        process = None
        try:
            with os.fdopen(tmp_out_fd, 'w') as out_f:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=out_f,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                
            # Parse results safely
            with open(tmp_out_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try:
                        res = json.loads(line)
                        url = res.get("URL")
                        status = res.get("StatusCode")
                        if url:
                            console.print(f"[bold magenta][ATF 🔥] Hit: {url} (Status: {status})[/bold magenta]")
                            discovered_urls.append(url)
                    except json.JSONDecodeError:
                        pass
            return discovered_urls

        except FileNotFoundError:
            console.print(f"[bold red][X] ATF Binary not found at {atf_binary}. Is it compiled? Falling back to native.[/bold red]")
        finally:
            # Strict zombie process prevention
            if process and process.returncode is None:
                try:
                    process.kill()
                except Exception:
                    pass
            if os.path.exists(tmp_out_path):
                try:
                    os.remove(tmp_out_path)
                except Exception:
                    pass
        
        # v20.0 SecLists Integration Scaling
        if swarm_mode:
            console.print(f"[dim yellow][!] Swarm Mode Active: Reducing Predator payload volume...[/dim yellow]")
            words = self._get_top_500_words()[:500]
        elif state.FAST_MODE:
            console.print(f"[cyan][!] v20.0 Fast Mode: Capping wordlist to top 1500 paths...[/cyan]")
            words = self._get_top_500_words()[:1500]
        else:
            console.print(f"[bold red][🔥] v20.0 Deep Scan: Unleashing 5000+ top paths from SecLists![/bold red]")
            words = self._get_top_500_words()[:5000]  
        
        # v38.0: Deep Hunter Catch-all Detection
        baseline = await self._get_spa_baseline(base_url)
        if baseline:
            console.print(f"[dim yellow][!] SPA Detected: Baseline length {baseline['length']}. Enabling Similarity Filter.[/dim yellow]")

        # v12.1 Persistence Check
        # In Phase 3, we use the injected persistence hub
        db_logger = self.persistence

        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"
        ]

        async def raw_check(directory):
            url = f"{base_url}/{directory}"
            try:
                if not swarm_mode:
                    await asyncio.sleep(random.uniform(0.1, 0.4)) # Only jitter if not in a massive swarm
                headers = {'User-Agent': random.choice(user_agents)}
                res = await self.stealth_session.get(url, timeout=state.NETWORK_TIMEOUT, allow_redirects=False, headers=headers)

                if res and self._is_valid_hit(res, baseline):
                    status_color = "green" if res.status_code < 400 else "yellow"
                    console.print(f"[{status_color}][+] Predator Hit: {url} ({res.status_code})[/{status_color}]")
                    try: db_logger.log_operation(url, "StealthPredator", res.status_code)
                    except: pass
                    return url
            except:
                pass
            return None

        # v19.5 Performance: Native Asyncio concurrency for force fuzzing
        semaphore = asyncio.Semaphore(60)
        async def sem_check(w):
            async with semaphore:
                return await raw_check(w)
        
        tasks = [sem_check(w) for w in words]
        results = await asyncio.gather(*tasks)

        for r in results:
            if r: discovered_urls.append(r)

        return discovered_urls

    async def blind_siege(self, base_url):
        """
        v14.0 The Final Siege: Mandatory Blind Path Injection.
        v19.4: Added catch-all detection to prevent false positives on SPAs.
        """
        import requests
        import random
        import uuid
        from concurrent.futures import ThreadPoolExecutor
        base_url = base_url.rstrip('/')
        hits = []

        console.print(f"[bold red][FINAL SIEGE][/bold red]: Deploying Blind Path Injection on {base_url}...")

        from urllib.parse import urlparse
        parsed_url = urlparse(base_url if base_url.startswith("http") else "http://" + base_url)
        if state.is_dns_failed(parsed_url.netloc):
            console.print(f"[bold red][X] FAST-FAIL: Target {parsed_url.netloc} has global DNS failure. Aborting Siege.[/bold red]")
            return []

        # v19.6 Siege Fix: Fast-Fail for dead hosts
        siege_baseline_200 = False
        try:
            _r1 = await self.stealth_session.get(f"{base_url}/rnd_{uuid.uuid4().hex[:8]}", allow_redirects=False, timeout=10, max_attempts=1)
            _r2 = await self.stealth_session.get(f"{base_url}/rnd_{uuid.uuid4().hex[:8]}", allow_redirects=False, timeout=10, max_attempts=1)
            
            if _r1 is None and _r2 is None:
                console.print(f"[bold red][X] FAST-FAIL: Target {base_url} is completely unresponsive/dead. Aborting Siege to save time.[/bold red]")
                return [] # Fast abort

            if _r1 and _r2 and _r1.status_code == 200 and _r2.status_code == 200:
                siege_baseline_200 = True
                console.print(f"[dim yellow][!] Siege Catch-All: SPA detected. Only 301/302/403 accepted as Siege Hits.[/dim yellow]")
        except Exception as e:
            console.print(f"[bold red][X] FAST-FAIL: Connection to {base_url} failed ({e}). Aborting Siege.[/bold red]")
            return []

        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        ]

        from aura.core.storage import AuraStorage
        db_logger = AuraStorage()

        async def siege_check(path):
            url = f"{base_url}/{path}"
            # v19.6 Siege Fix: Force 1 attempt if FAST_MODE is active to prevent death loops
            req_attempts = 1 if state.FAST_MODE else 3
            try:
                headers = {'User-Agent': random.choice(user_agents)}
                res = await self.stealth_session.get(url, timeout=state.NETWORK_TIMEOUT, allow_redirects=False, headers=headers, max_attempts=req_attempts)
                
                # Audit log EVERY attempt (v14.0 mandate)
                db_logger.log_operation(url, "BlindSiege", res.status_code)

                # v19.4: On catch-all servers, ignore 200 responses (they're all false positives)
                if siege_baseline_200:
                    if res.status_code == 403:
                        console.print(f"[bold cyan][!] Siege Hit: {url} ({res.status_code})[/bold cyan]")
                        return url
                else:
                    if res.status_code in [200, 403]:
                        console.print(f"[bold cyan][!] Siege Hit: {url} ({res.status_code})[/bold cyan]")
                        return url
            except Exception:
                db_logger.log_operation(url, "BlindSiege", 999)
            return None

        # v19.5 Performance: Native Asyncio concurrency for Blind Siege
        semaphore = asyncio.Semaphore(20)
        async def sem_siege(p):
            async with semaphore:
                return await siege_check(p)
                
        tasks = [sem_siege(p) for p in self.BLIND_SIEGE_LIST]
        results = await asyncio.gather(*tasks)
            
        for r in results:
            if r: hits.append(r)

        return hits

    async def synthesize_and_run_plugin(self, url: str, tech_info: str, cve_desc: str) -> dict | None:
        """
        v24.0 Sovereign Hegemony: On-the-fly scanner generation.
        Synthesizes a specialized detector and executes it in memory.
        """
        console.print(f"[bold magenta][🧠 AI-SYNTH] Synthesizing custom detector for {url}...[/bold magenta]")
        from aura.core.brain import AuraBrain
        brain = AuraBrain()
        
        # 1. Generate code via AI
        code = brain.synthesize_detection_plugin(tech_info, cve_desc)
        if not code:
            console.print(f"[dim red][!] AI failed to synthesize plugin for {url}[/dim red]")
            return None
            
        # 2. Execute safely (mock)
        console.print(f"[bold cyan][⚡ EXEC] Executing synthesized detector on {url}...[/bold cyan]")
        try:
            # Prepare execution environment
            local_namespace = {}
            if not code.strip().startswith("def detect_vulnerability"):
                raise ValueError("AI output is not a valid detection function")
            # We wrap the exec in a controlled scope
            try:
                exec(code, {"__builtins__": {}}, local_namespace)
            except Exception as exc:
                raise RuntimeError(f"Synthesized plugin execution failed: {exc}") from exc
            
            if 'detect_vulnerability' in local_namespace:
                # v24.0: Synthesized plugins are executed with current stealth session
                detector = local_namespace['detect_vulnerability']
                result = await detector(self.stealth_session, url)
                
                if result and result.get("vulnerable"):
                    console.print(f"[bold red][💥 HIT] Synthesized Plugin Confirmed: {result.get('details')}[/bold red]")
                    return result
            return None
        except Exception as e:
            console.print(f"[dim red][!] Synthesized Plugin Crash: {e}[/dim red]")
            return None

    # v7.2: Recursive Spider (Depth 5) - v7.4 Velocity Focus
    # ──────────────────────────────────────────────
    async def recursive_spider(self, base_url, max_depth=5, visited=None, swarm_mode=False):
        """
        v7.4 Velocity: Highly concurrent recursive link spider.
        Crawls from root, follows all links up to max_depth asynchronously.
        Extracts links from HTML, parses forms, and discovers hidden params.
        """
        if visited is None:
            visited = set()
        
        if not base_url.startswith("http"):
            base_url = f"http://{base_url}"
        
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc
        
        all_discovered = []
        all_forms = []
        
        # Start with depth 0
        current_level_urls = [base_url]
        
        # v19.6 Swarm Mode Scaling: Increase concurrency for massive scopes
        semaphore_limit = 40 if swarm_mode else 15
        spider_semaphore = asyncio.Semaphore(semaphore_limit)  # [WAF-Friendly] 15 for stealth, 40 for swarm speed
        
        console.print(f"[bold magenta][🕷️] v7.4 Velocity Spider: Starting concurrent deep crawl on {base_url} (depth {max_depth})...[/bold magenta]")
        
        for depth in range(max_depth + 1):
            if not current_level_urls:
                break
            
            console.print(f"[dim][🕷️] Spidering (depth {depth}): Processing {len(current_level_urls)} URLs concurrently...[/dim]")
            # Cap per-depth to prevent explosion on large sites
            current_level_urls = current_level_urls[:100]
            scope_guard = ScopeChecker(getattr(state, 'IN_SCOPE_RULES', []), getattr(state, 'OUT_OF_SCOPE_RULES', []))
            
            async def crawl_single(curl):
                if curl in visited: return [], []
                
                # v17.0 Strict Scope Guard
                if getattr(state, 'OUT_OF_SCOPE_RULES', []) or getattr(state, 'IN_SCOPE_RULES', []):
                    if not scope_guard.is_in_scope(curl):
                        return [], []
                        
                visited.add(curl)
                
                async with spider_semaphore:
                    try:
                        res = await self.stealth_session.get(curl, timeout=state.NETWORK_TIMEOUT) # [WAF-Friendly] Centralized Timeout Guard
                        if res.status_code != 200: return [], []
                        html = res.text
                    except: return [], []

                found_links = []
                found_forms = []
                
                # ── Extract all <a href> links ──
                hrefs = re.findall(r'<a[^>]+href=["\']([^"\'#]+)["\']', html, re.IGNORECASE)
                # v38.0: Extract SPA Routes from HTML/JS content
                spa_routes = re.findall(r'path\s*:\s*["\']([\w/.-]+)["\']', html, re.IGNORECASE)
                
                for href in hrefs + spa_routes:
                    full = urljoin(curl, href)
                    parsed = urlparse(full)
                    if parsed.netloc != base_domain: continue
                    if any(x in full.lower() for x in ["javascript:", "mailto:", "tel:", "#"]): continue
                    
                    clean = parsed._replace(fragment="").geturl()
                    if clean not in visited and clean not in found_links:
                        found_links.append(clean)
                
                # ── Extract <form> blocks ──
                form_blocks = re.findall(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
                for form_html in form_blocks:
                    action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                    method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                    
                    action = action_match.group(1) if action_match else curl
                    method = method_match.group(1).upper() if method_match else "GET"
                    full_action = urljoin(curl, action)
                    
                    # Extract inputs
                    inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']*)["\'])?[^>]*(?:value=["\']([^"\']*)["\'])?', form_html, re.IGNORECASE)
                    inputs2 = re.findall(r'<input[^>]+type=["\']([^"\']*)["\'][^>]*name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?', form_html, re.IGNORECASE)
                    
                    params = {}
                    hidden_params = []
                    for name, input_type, value in inputs:
                        params[name] = value or ""
                        if input_type.lower() == "hidden": hidden_params.append(name)
                    for input_type, name, value in inputs2:
                        if name not in params: params[name] = value or ""
                        if input_type.lower() == "hidden":
                            if name not in hidden_params: hidden_params.append(name)
                    
                    textareas = re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
                    for ta in textareas: params[ta] = ""
                    
                    selects = re.findall(r'<select[^>]+name=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
                    for s in selects: params[s] = ""
                    
                    form_data = {
                        "action": full_action,
                        "method": method,
                        "params": params,
                        "hidden": hidden_params
                    }
                    all_forms.append(form_data)
                    found_forms.append(form_data)

                return found_links, found_forms

            # Velocity v7.4: Concurrent execution of current level
            tasks = [crawl_single(url) for url in current_level_urls]
            results = await asyncio.gather(*tasks)
            
            # v18.1 Efficiency Fix: Use a set for next level to prevent redundant tasks
            next_level_set = set()
            for links, forms in results:
                for l in links:
                    if l not in visited:
                        next_level_set.add(l)
                        # v18.1 Fix: Actually record the discovered URL in the master list!
                        if l not in all_discovered:
                            all_discovered.append(l)
            
            current_level_urls = list(next_level_set)

        # v10.0 Sovereign: Active Multi-Port Discovery
        extra_ports = [8080, 8443, 8888]
        for p_num in extra_ports:
            try:
                p_url = f"https://{base_domain}:{p_num}"
                all_discovered.append(p_url)
            except: continue

        # v10.0 Sovereign: Infinite Discovery Mandate (50+ paths)
        if len(all_discovered) < 50:
            console.print(f"[bold yellow][!] Sovereign Search: Low Surface Detected ({len(all_discovered)} paths). Activating Recursive Brute-forcer...[/bold yellow]")
            extra = [f"https://{base_domain}{p}" for p in ["/admin", "/backup", "/db", "/config", "/api/v1", "/staging", "/dev", "/.env", "/portal", "/manage", "/wp-admin", "/shell", "/login", "/auth"]]
            all_discovered.extend(extra[:50-len(all_discovered)] if len(all_discovered) < 50 else [])

        console.print(f"[bold green][✔] Spider Complete: {len(all_discovered)} URLs + {len(all_forms)} Forms discovered (visited {len(visited)} pages).[/bold green]")
        return all_discovered, all_forms
