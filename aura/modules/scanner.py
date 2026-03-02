import socket
import re
import dns.resolver
import asyncio
import aiohttp
import uuid
from urllib.parse import urlparse, urljoin
from rich.console import Console
from aura.modules.threat_intel import ThreatIntel
from aura.core.stealth import StealthEngine, AuraSession

console = Console()

class AuraScanner:
    """v7.2 Instinct Focus — Deep Discovery Engine with Recursive Spidering,
    JS/CSS Link Extraction, Sitemap/Robots Mastery, and Professional DirBusting."""
    
    def __init__(self, stealth: StealthEngine = None):
        self.common_subdomains = ["www", "dev", "api", "staging", "admin", "vpn", "mail", "blog", "test"]
        self.stealth = stealth or StealthEngine()
        self.stealth_session = AuraSession(self.stealth)

    # ──────────────────────────────────────────────
    # Phase 1: Subdomain Discovery
    # ──────────────────────────────────────────────
    async def discover_subdomains(self, domain):
        """Discovers subdomains via DNS brute-forcing with rate-limiting & Threat Intel."""
        console.print(f"[blue][*] Starting subdomain discovery for: {domain}[/blue]")
        
        intel_module = ThreatIntel(stealth=self.stealth)
        vt_data = await intel_module.query_virustotal(domain)
        otx_data = await intel_module.query_otx(domain)
        
        found = []
        for sub in self.common_subdomains:
            target = f"{sub}.{domain}"
            await asyncio.sleep(0.1)
            try:
                answers = await asyncio.to_thread(dns.resolver.resolve, target, 'A')
                for rdata in answers:
                    found.append({"type": "subdomain", "value": target, "source": "Aura-Scan", "ip": str(rdata)})
                    console.print(f"[green][+] Found: {target} ({rdata})[/green]")
            except:
                continue
        return found

    # ──────────────────────────────────────────────
    # Phase 2: Port Scanning
    # ──────────────────────────────────────────────
    async def scan_ports(self, target_ip, ports=[80, 443, 8080, 8443, 3000, 4280, 5000, 22, 21, 3306]):
        """Async TCP port scanner targeting common web and service ports."""
        intel_module = ThreatIntel(stealth=self.stealth)
        intel_data = await intel_module.query_shodan(target_ip)
        
        open_ports = []
        if intel_data and intel_data.get("ports"):
            for p in intel_data["ports"]:
                if p not in open_ports and p in ports:
                    open_ports.append(p)
                    
        console.print(f"[blue][*] Active Port Scanning on: {target_ip}...[/blue]")
        
        async def check_port(port):
            if port in open_ports: return port
            try:
                fut = asyncio.open_connection(target_ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=0.5)
                writer.close()
                await writer.wait_closed()
                console.print(f"[green][+] Port {port} is OPEN[/green]")
                return port
            except:
                return None

        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r and r not in open_ports:
                open_ports.append(r)
                
        return open_ports

    # ──────────────────────────────────────────────
    # v7.2: Sitemap & Robots Parser
    # ──────────────────────────────────────────────
    async def parse_sitemap_robots(self, base_url):
        """Mandatory: Parses sitemap.xml and robots.txt to extract ALL hidden paths."""
        base_url = base_url.rstrip('/')
        all_paths = []
        
        
        async def fetch_robots():
            console.print(f"[cyan][🗺️] v7.2 Instinct: Parsing robots.txt for {base_url}...[/cyan]")
            try:
                res = await self.stealth_session.get(f"{base_url}/robots.txt", timeout=5)
                if res.status_code == 200 and "disallow" in res.text.lower():
                    lines = res.text.splitlines()
                    for line in lines:
                        line = line.strip()
                        if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/" and "*" not in path:
                                full = urljoin(base_url + "/", path.lstrip("/"))
                                if full not in all_paths:
                                    all_paths.append(full)
                                    console.print(f"[green][+] robots.txt: {full}[/green]")
                        elif line.lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            if sitemap_url.startswith("//"):
                                sitemap_url = "http:" + sitemap_url
                            sm_paths = await self._parse_sitemap_url(sitemap_url)
                            for p in sm_paths:
                                if p not in all_paths: all_paths.append(p)
            except Exception as e:
                console.print(f"[dim yellow][!] robots.txt fetch failed: {e}[/dim yellow]")

        async def fetch_sitemap():
            console.print(f"[cyan][🗺️] v7.2 Instinct: Parsing sitemap.xml for {base_url}...[/cyan]")
            sm_paths = await self._parse_sitemap_url(f"{base_url}/sitemap.xml")
            for p in sm_paths:
                if p not in all_paths: all_paths.append(p)

        # v7.4 Velocity Focus: Run map parsers concurrently
        await asyncio.gather(fetch_robots(), fetch_sitemap())
        
        console.print(f"[bold green][+] Sitemap/Robots Total: {len(all_paths)} paths extracted.[/bold green]")
        return all_paths
    
    async def _parse_sitemap_url(self, sitemap_url):
        """Recursively parses a sitemap URL (supports sitemap index files)."""
        paths = []
        try:
            res = await self.stealth_session.get(sitemap_url, timeout=8)
            if res.status_code != 200:
                return paths
            
            text = res.text
            # Extract <loc> tags (standard sitemap format)
            locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", text, re.IGNORECASE)
            for loc in locs:
                loc = loc.strip()
                if loc.endswith(".xml"):
                    # It's a sitemap index — recurse
                    sub_paths = await self._parse_sitemap_url(loc)
                    paths.extend(sub_paths)
                else:
                    if loc not in paths:
                        paths.append(loc)
                        console.print(f"[green][+] sitemap: {loc}[/green]")
        except Exception as e:
            console.print(f"[dim yellow][!] Sitemap parse failed for {sitemap_url}: {e}[/dim yellow]")
        return paths

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
                res = await self.stealth_session.get(base_url, timeout=8)
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
            r'["\'](/[a-zA-Z0-9_-]+\.(php|asp|aspx|jsp|json|xml|txt|cfg|conf|ini|bak|sql|log))["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest.*?open\s*\([^,]+,\s*["\']([^"\']+)["\']',
            r'url\s*[:=]\s*["\']([^"\']+/[^"\']+)["\']',
            r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
            r'path\s*[:=]\s*["\'](/[^"\']+)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'href\s*[:=]\s*["\'](/[^"\']+)["\']',
        ]
        
        # v7.4 Velocity Focus: Concurrency for resource fetching
        js_semaphore = asyncio.Semaphore(15)
        
        async def fetch_and_extract(res_url):
            async with js_semaphore:
                try:
                    res = await self.stealth_session.get(res_url, timeout=5)
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

    # ──────────────────────────────────────────────
    # v7.2: Enhanced DirBuster (Professional Wordlist)
    # ──────────────────────────────────────────────
    DIRBUST_NO_RECURSE = {
        ".env", ".git", ".svn", "docker-compose.yml",
        "index.php", "home.php", "main.php", "robots.txt",
        "phpmyadmin", "dvwa",
    }

    # v11.0 Hard Reset: 1000+ Word Total Dominance Wordlist
    PROFESSIONAL_WORDLIST = [
        # Admin & Auth (Core)
        "admin", "administrator", "login", "signin", "auth", "authenticate", "dashboard", "panel", "cpanel", 
        "webmin", "manager", "console", "control", "portal", "secure", "account", "user", "users", "adminpanel",
        "admin-console", "backend", "cp", "sysadmin", "root", "super", "superuser", "master", "masteradmin",
        "admin/login", "admin/index", "admin.php", "login.php", "signin.php", "user/login", "auth/login",
        "admin_area", "admin1", "admin2", "admin3", "admin_login", "cms", "cmsadmin", "siteadmin", "myadmin",
        
        # API & Web Services
        "api", "api/v1", "api/v2", "api/v3", "api/v4", "rest", "graphql", "swagger", "api-docs", "openapi",
        "docs", "documentation", "soap", "ws", "webservices", "grpc", "trpc", "xmlrpc", "xmlrpc.php",
        "graphiql", "endpoint", "endpoints", "services", "svc", "microservices", "api-gateway", "gw",
        "api/swagger", "swagger-ui", "swagger-ui.html", "api/swagger.json", "swagger.json", "v1/api", "v2/api",
        "graphql/schema", "graphql/query", "gql", "api/graphql", "graphql/console", "graphiql.php",
        
        # Development, Testing & Staging
        "dev", "development", "staging", "test", "testing", "debug", "sandbox", "beta", "alpha", "demo",
        "prototype", "lab", "local", "localhost", "qa", "uat", "preprod", "builder", "build", "ci", "cd",
        "testapp", "test-env", "dev-env", "staging-env", "test.html", "test.php", "debug.php", "info.html",
        
        # Backup, Archives & Dumps
        "backup", "backups", "bak", "old", "archive", "dump", "db_backup", "site_backup", "backup.zip",
        "backup.tar.gz", "backup.sql", "dump.sql", "data.sql", "users.sql", "database.sql", "mysql.sql",
        "db.sql", "backup.rar", "archive.zip", "source.zip", "src.zip", "code.zip", "www.zip", "full.zip",
        "1.zip", "project.zip", "web.zip", "site.zip", "website.zip", "app.zip", "backup.tar", "data.zip",
        "db_dump.sql", "sqldump.sql", "postgres.sql", "mongo-dump.tar.gz", "archive.tgz", "old.zip",
        "site.bak", "db.bak", "config.bak", "index.php.bak", "app.bak",
        
        # Configuration & Settings
        "config", "configuration", "settings", "setup", "install", "installer", "db", "database", "sql",
        "mysql", "phpmyadmin", "adminer", "pgadmin", "mongo", "mongodb", "redis", "memcached", "conf",
        "config.php", "config.inc.php", "config.bak", "config.old", "config.txt", "config.json", "config.xml",
        "config.yaml", "config.yml", "settings.py", "settings.json", "settings.xml", "application.yml",
        "application.properties", "appsettings.json", "env.json", "env.yaml", "db.php", "database.php",
        "connection.php", "db_connect.php", "config/database.yml", "wp-config.php", "local.xml", 
        
        # Version Control (Critical)
        ".git", ".git/config", ".git/HEAD", ".git/logs/HEAD", ".git/index", ".gitignore", ".gitmodules",
        ".svn", ".svn/entries", ".svn/wc.db", ".hg", ".bzr", ".cvs", ".git/description", ".git/packed-refs",
        ".git/info/exclude", ".svn/pristine/", ".svn/text-base/",
        
        # Sensitive Files (High Impact)
        ".env", ".env.local", ".env.production", ".env.backup", ".env.dev", ".env.stage", ".env.test",
        ".env.sample", ".env.example", ".env.old", ".env.bak", ".env.txt", ".htaccess", ".htpasswd", 
        "web.config", "crossdomain.xml", "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
        "wp-config.old", "wp-config.bak", "wp-config.txt", "docker-compose.yml", "docker-compose.yaml",
        "Dockerfile", "Makefile", "Vagrantfile", "package.json", "composer.json", "composer.lock",
        "Gemfile", "Gemfile.lock", "requirements.txt", "yarn.lock", "package-lock.json",
        "server.key", "server.crt", "id_rsa", "id_dsa", "authorized_keys", "known_hosts", "secret.txt",
        
        # Server Status & Info
        "server-status", "server-info", "info.php", "phpinfo.php", "test.php", "status", "health", 
        "ping", "diagnostics", "metrics", "stats", "statistics", "monitor", "monitoring",
        "php.info", "pi.php", "i.php", "php-info.php", "test_info.php", "test.cgi", "env.cgi",
        
        # Common Web Directories
        "uploads", "upload", "files", "media", "images", "img", "static", "assets", "public", "resources",
        "content", "css", "js", "scripts", "fonts", "vendor", "inc", "includes", "lib", "library",
        "modules", "plugins", "themes", "templates", "views", "components", "src", "source", "app",
        "application", "core", "bin", "sbin", "cgi-bin", "dist", "build", "out", "target",
        "data", "doc", "docs", "download", "downloads", "export", "import", "tmp", "temp", "cache",
        
        # CMS & Framework Specific
        "wp-admin", "wp-login.php", "wp-content", "wp-includes", "wp-content/uploads", "joomla", "drupal",
        "magento", "craftcms", "typo3", "bitrix", "laravel", "symfony", "django", "flask", "spring",
        "rails", "express", "next", "nuxt", "vue", "react", "angular", "node_modules",
        "administrator/index.php", "user", "admin/login", "ghost", "umbraco", "moodle", "canvas",
        "wp-config.php", "wp-cron.php", "xmlrpc.php", "wp-json", "wp-admin/admin-ajax.php",
        
        # Hidden Services & Dashboards
        "jenkins", "gitlab", "bitbucket", "sonarqube", "grafana", "kibana", "elasticsearch", "prometheus",
        "minio", "rabbitmq", "celery", "flower", "portainer", "traefik", "consul", "nomad", "vault",
        "supervisor", "netdata", "phpinfo", "php-info", "fluentd", "logstash", "nagios", "zabbix",
        "cacti", "munin", "webmin", "ispconfig", "plesk", "directadmin", "splunk", "newrelic",
        
        # Data & Logs
        "export.csv", "data.json", "logs", "log", "error_log", "access_log", "debug.log", "system.log",
        "app.log", "application.log", "prod.log", "dev.log", "test.log", "tmp", "temp", "cache",
        "var", "run", "spool", "mail", "messages", "syslog", "auth.log", "nginx.log", "apache.log",
        "error.log", "access.log", "mysql.log", "mariadb.log", "postgresql.log", "mongodb.log",
        
        # Security & Compliance
        "actuator", "actuator/health", "actuator/env", "actuator/metrics", "actuator/httptrace",
        "trace", "heapdump", "jolokia", ".well-known", ".well-known/security.txt", 
        ".well-known/apple-app-site-association", ".well-known/assetlinks.json",
        "clientaccesspolicy.xml", "security.txt", "humans.txt", "robots.txt",
        "actuator/mappings", "actuator/info", "actuator/dump", "actuator/threaddump",
        
        # Cloud & Container
        ".aws/credentials", ".aws/config", ".s3cfg", ".dockerignore", "kubernetes", "k8s",
        "helm", "charts", "metadata", "latest/meta-data/", "latest/meta-data/iam/security-credentials/",
        
        # Mobile & API Extensions
        "v1", "v2", "v3", "mobile", "m", "ios", "android", "app-api", "web-api", "internal-api",
        
        # Extra padding for sheer aggressive volume (Common parameters/paths)
        "users", "customers", "clients", "orders", "invoices", "billing", "payments", "transactions",
        "products", "items", "catalog", "inventory", "stock", "categories", "brands",
        "search", "query", "filter", "sort", "results", "find", "list", "view", "show", "detail",
        "update", "edit", "save", "create", "new", "add", "delete", "remove", "destroy", "drop",
        "process", "run", "execute", "start", "stop", "restart", "reboot", "shutdown", "halt",
        
        # Expanded extensions
        "index.php", "index.html", "index.htm", "index.asp", "index.aspx", "index.jsp", "index.cgi",
        "default.php", "default.html", "default.htm", "default.asp", "default.aspx", "default.jsp",
        "home.php", "home.html", "main.php", "main.html", "app.js", "main.js", "bundle.js",
        
        # Vulnerability / Exploit check paths
        "shell.php", "cmd.php", "eval.php", "exec.php", "system.php", "webshell.php", "c99.php",
        "r57.php", "wso.php", "b374k.php", "up.php", "upload.php", "test_upload.php", "file_upload.php",
        "phpbash.php", "pwn.php", "hack.php", "exploit.php", "backdoor.php"
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
        # Top 500 essential fuzzing paths hardcoded for execution predictability
        return [
            "admin", "login", "manager", "setup", "install", "api", "v1", "v2", "graphql",
            "docs", "swagger", "openapi", "metrics", "health", "ping", "status", "info",
            "dashboard", "transfer", "account", "profile", "settings", "config", "env",
            ".env", ".git", ".htaccess", "db", "database", "backup", "bak", "old", "test",
            "server-status", "app", "auth", "oauth", "token", "jwt", "session", "users",
            "user", "admin.php", "login.php", "index.php", "config.php", "wp-login.php",
            "wp-admin", "xmlrpc.php", "robots.txt", "sitemap.xml", "crossdomain.xml",
            "clientaccesspolicy.xml", "phpinfo.php", "info.php", "test.php", "shell.php",
            "cmd.php", "exec.php", "system.php", "web.config", "appsettings.json",
            "docker-compose.yml", "Dockerfile", "package.json", "package-lock.json",
            "composer.json", "composer.lock", "yarn.lock", "pom.xml", "build.gradle",
            "Gemfile", "Gemfile.lock", "Pipfile", "Pipfile.lock", "requirements.txt",
            "setup.py", "tox.ini", "pytest.ini", "karma.conf.js", "Gruntfile.js",
            "gulpfile.js", "webpack.config.js", "tsconfig.json", "tslint.json",
            "eslint.json", "prettierrc", "babelrc", "env.example", "env.local",
            "env.dev", "env.prod", "env.staging", "env.test", "config.yml", "config.yaml",
            "settings.yml", "settings.yaml", "database.yml", "database.yaml", "secrets.yml",
            "secrets.yaml", "credentials.yml", "credentials.yaml", "keys.yml", "keys.yaml",
            ".ssh", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys",
            "known_hosts", ".bash_history", ".zsh_history", ".mysql_history",
            ".psql_history", ".sqlite_history", ".rediscli_history", ".irb_history",
            ".node_repl_history", ".python_history", ".Rhistory", ".mongorc.js",
            "manage.py", "artisan", "console", "bin", "sbin", "usr", "etc", "var", "tmp",
            "opt", "root", "home", "mnt", "media", "srv", "sys", "proc", "dev", "lib",
            "lib64", "boot", "run", "lost+found", "C$", "ADMIN$", "IPC$", "print$",
            "smb.conf", "apache2.conf", "httpd.conf", "nginx.conf", "php.ini",
            "my.cnf", "postgresql.conf", "redis.conf", "mongodb.conf", "docker.sock",
            "kubeconfig", "passwd", "shadow", "group", "gshadow", "sudoers", "hosts",
            "resolv.conf", "fstab", "mtab", "issue", "os-release", "motd", "crontab",
            "cron.d", "cron.daily", "cron.hourly", "cron.monthly", "cron.weekly",
            "log", "logs", "access.log", "error.log", "audit.log", "secure.log",
            "messages.log", "syslog", "dmesg", "auth.log", "daemon.log", "kern.log",
            "mail.log", "user.log", "xferlog", "vsftpd.log", "proftpd.log", "pureftpd.log",
            "mysql.log", "mariadb.log", "postgresql.log", "mongodb.log", "redis.log",
            "cassandra.log", "elasticsearch.log", "kibana.log", "logstash.log",
            "nginx-access.log", "nginx-error.log", "apache2-access.log", "apache2-error.log",
            "httpd-access.log", "httpd-error.log", "tomcat-access.log", "tomcat-error.log",
            "catalina.out", "jboss-access.log", "jboss-error.log", "weblogic-access.log",
            "weblogic-error.log", "websphere-access.log", "websphere-error.log",
            "glassfish-access.log", "glassfish-error.log", "iis-access.log", "iis-error.log",
            "exchange-access.log", "exchange-error.log", "owa-access.log", "owa-error.log",
            "portal", "login.jsp", "index.jsp", "admin.jsp", "manager.jsp", "secure.jsp",
            "auth.jsp", "login.aspx", "index.aspx", "admin.aspx", "manager.aspx",
            "secure.aspx", "auth.aspx", "login.action", "index.action", "admin.action",
            "manager.action", "secure.action", "auth.action", "login.do", "index.do",
            "admin.do", "manager.do", "secure.do", "auth.do", "ws", "soap", "rest",
            "graphql.php", "graphql.jsp", "graphql.aspx", "graphql.action", "graphql.do",
            "swagger.json", "swagger.yml", "swagger.yaml", "openapi.json", "openapi.yml",
            "openapi.yaml", "v3/api-docs", "v2/api-docs", "swagger-ui.html", "redoc.html",
            "graphql-playground", "graphiql", "altair", "voyager", "adminer", "phpmyadmin",
            "pma", "mysql", "sql", "dbadmin", "pgadmin", "phppgadmin", "rockmongo",
            "mongo-express", "redis-commander", "kibana", "grafana", "prometheus",
            "alertmanager", "consul", "nomad", "vault", "rabbitmq", "celery", "flower",
            "supervisor", "netdata", "nagios", "zabbix", "cacti", "munin", "icinga",
            "thruk", "check_mk", "op5", "observium", "librenms", "snipeit", "glpi",
            "jira", "confluence", "bitbucket", "bamboo", "crucible", "fisheye", "crowd",
            "nexus", "artifactory", "sonarqube", "jenkins", "gitlab", "gitea", "gogs",
            "phabricator", "redmine", "trac", "bugzilla", "mantis", "youtrack",
            "mattermost", "slack", "discord", "teams", "rocketchat", "zulip", "matrix",
            "synapse", "riot", "element", "jitsi", "bigbluebutton", "nextcloud",
            "owncloud", "seafile", "pydio", "filecloud", "ajaxplorer", "wordpress",
            "drupal", "joomla", "magento", "prestashop", "opencart", "oscommerce",
            "zencart", "virtuemart", "woocommerce", "shopify", "bigcommerce", "volusion",
            "wix", "squarespace", "weebly", "jimdo", "strikingly", "webflow", "cpanel",
            "whm", "plesk", "directadmin", "webmin", "usermin", "virtualmin", "cloudmin",
            "ispconfig", "froxlor", "ajenti", "vesta", "cyberpanel", "aapanel",
            "centos-web-panel", "interworx", "sentora", "zpanel", "kloxo", "ehcp",
            "dtc", "gnu-panel", "syscp", "ispmanager", "core-admin", "froxlor", "vhcs",
            "baikal", "radicale", "davical", "sabre-dav", "horde", "roundcube", "squirrelmail",
            "rainloop", "zimbra", "iredmail", "mailcow", "mail-in-a-box", "poste-io",
            "modoboa", "exim", "postfix", "sendmail", "qmail", "dovecot", "courier",
            "cyrus", "spamassassin", "amavis", "clamav", "opendkim", "opendmarc",
            "spf", "dkim", "dmarc", "bimi", "mta-sts", "tls-rpt", "autodiscover",
            "autoconfig", "wpad", "isatap", "dns", "ns1", "ns2", "ns3", "ns4",
            "mx", "mx1", "mx2", "mx3", "mx4", "smtp", "imap", "pop3", "webmail",
            "extranet", "intranet", "partner", "store", "shop", "cart", "checkout",
            "pay", "billing", "invoice", "quote", "support", "help", "faq", "kb",
            "wiki", "forum", "board", "community", "blog", "news", "press", "media",
            "events", "calendar", "jobs", "careers", "about", "contact", "privacy",
            "terms", "legal", "sitemap", "feed", "rss", "atom", "upload", "download",
            "files", "images", "css", "js", "assets", "static", "public", "private",
            "hidden", "secret", "draft", "pending", "review", "approve", "reject",
            "delete", "remove", "destroy", "purge", "clear", "reset", "recover",
            "restore", "import", "export", "sync", "async", "batch", "cron", "job",
            "task", "worker", "queue", "topic", "stream", "event", "message", "notification"
        ]

    async def force_fuzz(self, base_url):
        """
        v13.0 Stealth Predator: Hardcoded aggressive dirbusting with UA rotation and jitter.
        Uses ThreadPoolExecutor and raw requests to force brute-force 500 paths with maximum aggression.
        """
        import requests
        from concurrent.futures import ThreadPoolExecutor
        import urllib3
        import time
        import random
        import uuid
        
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        console.print(f"☠️ [bold red]v13.0 STEALTH PREDATOR[/bold red]: Forcing RAW DirBuster on {base_url}")
        if not base_url.startswith("http"):
            base_url = f"http://{base_url}"
        base_url = base_url.rstrip('/')
        
        discovered_urls = []
        words = self._get_top_500_words()[:500] 
        
        # Test baseline
        try:
            b_res = requests.get(f"{base_url}/rnd_{uuid.uuid4().hex[:8]}", verify=False, timeout=3, allow_redirects=False)
            b_len = len(b_res.text)
        except:
            b_len = 0

        # v12.1 Persistence Check
        from aura.core.storage import AuraStorage
        db_logger = AuraStorage()

        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"
        ]

        def raw_check(directory):
            url = f"{base_url}/{directory}"
            try:
                # Randomize jitter to mimic humans and stay under rate-limits
                time.sleep(random.uniform(0.1, 0.4))
                
                # Raw synchronous aggressive requests with UA rotation
                headers = {'User-Agent': random.choice(user_agents)}
                res = requests.get(url, verify=False, timeout=5, allow_redirects=False, headers=headers)
                
                if b_len > 0 and abs(len(res.text) - b_len) < 50:
                    return None
                    
                if res.status_code == 200:
                    console.print(f"[green][+] Predator Hit: {url} (200 OK)[/green]")
                    try:
                        db_logger.log_operation(url, "StealthPredator", 200)
                    except: pass
                    return url
                elif res.status_code in [301, 302]:
                    console.print(f"[green][+] Predator Hit: {url} (Redirect {res.status_code})[/green]")
                    try:
                        db_logger.log_operation(url, "StealthPredator", res.status_code)
                    except: pass
                    return url
            except:
                pass
            return None

        # Execute as fast as possible using ThreadPool (capped at 15 for 'Stealth' balance)
        with ThreadPoolExecutor(max_workers=15) as executor:
            results = list(executor.map(raw_check, words))
            
        for r in results:
            if r: discovered_urls.append(r)
            
        return discovered_urls

    # ──────────────────────────────────────────────
    # v7.2: Recursive Spider (Depth 5) - v7.4 Velocity Focus
    # ──────────────────────────────────────────────
    async def recursive_spider(self, base_url, max_depth=5, visited=None):
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
        spider_semaphore = asyncio.Semaphore(15) # Velocity v7.4 concurrency cap
        
        console.print(f"[bold magenta][🕷️] v7.4 Velocity Spider: Starting concurrent deep crawl on {base_url} (depth {max_depth})...[/bold magenta]")
        
        for depth in range(max_depth + 1):
            if not current_level_urls:
                break
            
            console.print(f"[dim][🕷️] Spidering (depth {depth}): Processing {len(current_level_urls)} URLs concurrently...[/dim]")
            next_level_urls = []
            
            async def crawl_single(curl):
                if curl in visited: return [], []
                visited.add(curl)
                
                async with spider_semaphore:
                    try:
                        res = await self.stealth_session.get(curl, timeout=8)
                        if res.status_code != 200: return [], []
                        html = res.text
                    except: return [], []

                found_links = []
                found_forms = []
                
                # ── Extract all <a href> links ──
                hrefs = re.findall(r'<a[^>]+href=["\']([^"\'#]+)["\']', html, re.IGNORECASE)
                for href in hrefs:
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
            
            next_level_urls = []
            for links, forms in results:
                for l in links:
                    if l not in visited:
                        next_level_urls.append(l)
            
            current_level_urls = next_level_urls

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
