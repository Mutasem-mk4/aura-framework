import subprocess
import json
import os
import sys
import socket
import time
from typing import List, Dict, Any, Optional
from aura.core import state

class VeritasClient:
    """v3.0 Omega: Persistent JSON-RPC 2.0 client for Nexus."""
    def __init__(self, host="127.0.0.1", port=50051):
        self.host = host
        self.port = port
        self.sock = None
        self._id = 0

    def connect(self, retries=5):
        for i in range(retries):
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10)
                self.sock.connect((self.host, self.port))
                return True
            except:
                time.sleep(1)
        return False

    def call(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        if not self.sock:
            if not self.connect(): return {"error": "Connection failed"}
        
        self._id += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self._id
        }
        try:
            self.sock.sendall(json.dumps(payload).encode() + b"\n")
            response = self.sock.recv(16384).decode().strip()
            return json.loads(response)
        except Exception as e:
            self.sock = None # Reset connection on error
            return {"error": str(e)}

class NexusBridge:
    """
    Aura Nexus: High-Performance Go Bridge.
    Orchestrates the execution of the Go-based networking core for maximum speed.
    """
    
    # Burp API configuration
    BURP_API_URL = "http://127.0.0.1:8090"
    
    def __init__(self, persistence=None, telemetry=None, brain=None, **kwargs):
        # Store dependencies
        self.db = persistence  # Legacy compatibility
        self.persistence = persistence
        self.telemetry = telemetry
        self.brain = brain
        
        # Paths are absolute to prevent resolution errors
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.nexus_path = os.path.join(self.base_dir, "nexus", "nexus.exe")
        self.veritas_process = None
        self.veritas_port = 50051
        self.veritas = VeritasClient(port=self.veritas_port)
        
        # Graceful handling if nexus binary is missing
        if not os.path.exists(self.nexus_path):
            import logging
            logging.getLogger("aura.nexus").warning(f"Nexus binary not found at {self.nexus_path}. Running in stub mode.")
    
    def route_finding_to_burp(self, finding: Dict[str, Any]) -> bool:
        """Route a finding to Burp Suite via REST API (port 8090)."""
        try:
            import requests
            url = finding.get("target_value") or finding.get("url")
            if not url:
                return False
            
            # Send to Burp proxy for further analysis
            response = requests.post(
                f"{self.BURP_API_URL}/proxy",
                json={"url": url},
                timeout=10
            )
            return response.status_code == 200
        except Exception:
            return False
    
    def get_burp_sitemap(self) -> List[Dict[str, Any]]:
        """Fetch sitemap from Burp Suite API."""
        try:
            import requests
            response = requests.get(f"{self.BURP_API_URL}/sitemap", timeout=10)
            if response.status_code == 200:
                return response.json().get("sitemap", [])
        except Exception:
            pass
        return []

    def start_veritas(self, port: int = 50051):
        """Starts the long-running Veritas service backbone."""
        if self.veritas_process: return
        
        self.veritas_port = port
        self.veritas.port = port
        
        cmd = [self.nexus_path, "-mode=veritas", f"-target={port}"]
        self.veritas_process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
        )
        time.sleep(2)
        if not self.veritas.connect():
            # v4.0: Silent fail for library use, log for diag
            pass

    def stop_veritas(self):
        if self.veritas_process:
            self.veritas_process.terminate()
            self.veritas_process = None
            self.veritas.sock = None

    def scan_ports(self, ip: str, ports: List[int], concurrency: int = 500, timeout: int = 1000) -> List[Dict[str, Any]]:
        """Executes ultra-fast port scanning via Go logic."""
        ports_json = json.dumps(ports)
        cmd = [
            self.nexus_path,
            "-mode=scan",
            f"-target={ip}",
            f"-ports={ports_json}",
            f"-c={concurrency}",
            f"-t={timeout}"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except Exception as e:
            print(f"[!] Nexus Error (Scan): {e}")
            return []

    def probe_urls(self, urls: List[str], concurrency: int = 200, timeout: int = 2000, stealth: bool = None, proxies: List[str] = None) -> List[Dict[str, Any]]:
        """Executes ultra-fast HTTP probing via Go logic."""
        if stealth is None:
            stealth = state.GHOST_MODE
        
        urls_json = json.dumps(urls)
        cmd = [
            self.nexus_path,
            "-mode=probe",
            f"-target={urls_json}",
            f"-c={concurrency}",
            f"-t={timeout}"
        ]
        if stealth:
            cmd.append("-stealth")
        
        if proxies:
            cmd.append(f"-proxies={json.dumps(proxies)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except Exception as e:
            print(f"[!] Nexus Error (Probe): {e}")
            return []

    def race_burst(self, url: str, data: Dict[str, Any], concurrency: int = 25, timeout: int = 10000, stealth: bool = None, proxies: List[str] = None) -> List[Dict[str, Any]]:
        """Executes a high-precision synchronized race condition burst."""
        if stealth is None:
            stealth = state.GHOST_MODE
            
        data_json = json.dumps(data)
        cmd = [
            self.nexus_path,
            "-mode=race",
            f"-target={url}",
            f"-ports={data_json}", # reusing ports flag for arbitrary data
            f"-c={concurrency}",
            f"-t={timeout}"
        ]
        if stealth:
            cmd.append("-stealth")
        
        if proxies:
            cmd.append(f"-proxies={json.dumps(proxies)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except Exception as e:
            print(f"[!] Nexus Error (Race): {e}")
            return []

    def smuggle_check(self, url: str, timeout: int = 5000) -> List[Dict[str, Any]]:
        """Executes raw HTTP smuggling detection logic via Go core."""
        cmd = [
            self.nexus_path,
            "-mode=smuggle",
            f"-target={url}",
            f"-t={timeout}"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except Exception as e:
            print(f"[!] Nexus Error (Smuggle): {e}")
            return []

    def start_proxy(self, port: int = 8081, log_file: str = "aura_traffic.json"):
        """Requests Veritas to spawn a high-performance MITM proxy worker."""
        # Ensure Veritas is running
        self.start_veritas()
        
        res = self.veritas.call("start_proxy", {"port": port, "log_file": log_file})
        if res.get("result"):
            print(f"[*] Veritas: Proxy worker spawned on port {port}. Logging to {log_file}")
            return True
        else:
            print(f"[!] Veritas: Failed to spawn proxy: {res.get('error')}")
            return False

    def get_health(self):
        """Query Veritas for system and engine health status."""
        return self.veritas.call("get_health")


class BurpController:
    """
    Aura-Burp Bridge: Integrates with Burp Suite Professional/Community REST API (port 8090).
    Enables passive scanning, sitemap access, and active proxying.
    Note: Community Edition has limited API functionality.
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8090):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self._session = None
    
    @property
    def session(self):
        if self._session is None:
            import requests
            self._session = requests.Session()
        return self._session
    
    def is_available(self) -> bool:
        """Check if Burp REST API is accessible."""
        try:
            resp = self.session.get(f"{self.base_url}/sitemap", timeout=2)
            return resp.status_code in [200, 401, 403]
        except Exception:
            return False
    
    def get_sitemap(self) -> list:
        """Fetch the current sitemap from Burp."""
        try:
            resp = self.session.get(f"{self.base_url}/sitemap", timeout=10)
            if resp.status_code == 200:
                return resp.json().get("sitemap", [])
            return []
        except Exception as e:
            print(f"[!] Burp API Error: {e}")
            return []
    
    def send_to_proxy(self, url: str, method: str = "GET", headers: dict = None, data: str = None) -> bool:
        """Send a request through Burp's proxy for interception."""
        try:
            payload = {
                "url": url,
                "method": method,
            }
            if headers:
                payload["headers"] = headers
            if data:
                payload["body"] = data
            
            resp = self.session.post(f"{self.base_url}/proxy", json=payload, timeout=10)
            return resp.status_code == 200
        except Exception as e:
            print(f"[!] Burp Proxy Error: {e}")
            return False
    
    def scan(self, url: str) -> dict:
        """Trigger an active scan on a target URL (Professional only)."""
        try:
            resp = self.session.post(
                f"{self.base_url}/scan", 
                json={"urls": [url]},
                timeout=30
            )
            return resp.json() if resp.status_code == 200 else {}
        except Exception as e:
            return {"error": str(e)}

    async def async_scan(self, url: str) -> dict:
        """Async wrapper for scan."""
        import asyncio
        return await asyncio.to_thread(self.scan, url)
    
    async def async_get_sitemap(self) -> list:
        """Async wrapper for get_sitemap."""
        return await asyncio.to_thread(self.get_sitemap)

    async def async_send_to_proxy(self, url: str, method: str = "GET", headers: dict = None, data: str = None) -> bool:
        """Async wrapper for send_to_proxy."""
        return await asyncio.to_thread(self.send_to_proxy, url, method, headers, data)

if __name__ == "__main__":
    bridge = NexusBridge()
    print("[*] Testing Nexus Bridge - Scan...")
    print(bridge.scan_ports("127.0.0.1", [80, 443, 3306, 8080]))
    print("[*] Testing Nexus Bridge - Probe...")
    print(bridge.probe_urls(["https://google.com", "http://example.com"]))
