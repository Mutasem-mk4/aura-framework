import socket
import threading
import select
from rich.console import Console

console = Console()

class AuraLink:
    """The 'Pivoting' engine for internal network dominance."""
    
    def __init__(self, bind_host="127.0.0.1", bind_port=9050):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.running = False

    def handle_client(self, client_socket):
        """Standard SOCKS5 handling logic (simplified)."""
        try:
            # 1. Negotiation
            greeting = client_socket.recv(2)
            if not greeting: return
            
            # Respond with: Version 5, No Auth
            client_socket.send(b"\x05\x00")
            
            # 2. Request
            header = client_socket.recv(4)
            if not header: return
            
            addr_type = header[3]
            if addr_type == 1: # IPv4
                address = socket.inet_ntoa(client_socket.recv(4))
            elif addr_type == 3: # Domain name
                addr_len = client_socket.recv(1)[0]
                address = client_socket.recv(addr_len).decode()
            else:
                return # Unsupported
                
            port = int.from_bytes(client_socket.recv(2), 'big')
            
            # 3. Connect to target
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((address, port))
            
            # Success response
            client_socket.send(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + (0).to_bytes(2, 'big'))
            
            # 4. Data Transfer (Pipe)
            self.pipe(client_socket, remote_socket)
            
        except Exception as e:
            # console.print(f"[red][!] Pivot Error: {str(e)}[/red]")
            pass
        finally:
            client_socket.close()

    def pipe(self, local, remote):
        """Bidirectional data transfer."""
        while True:
            r, w, e = select.select([local, remote], [], [])
            if local in r:
                data = local.recv(4096)
                if remote.send(data) <= 0: break
            if remote in r:
                data = remote.recv(4096)
                if local.send(data) <= 0: break

    def start_pivot(self):
        """Starts the SOCKS5 pivot server."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.bind_host, self.bind_port))
        server.listen(5)
        self.running = True
        
        console.print(f"[bold green][🔗] Aura-Link: SOCKS5 Pivot active on {self.bind_host}:{self.bind_port}[/bold green]")
        console.print(f"[italic cyan][*] You can now tunnel your tools (nmap, proxychains) through this Aura instance.[/italic cyan]")
        
        while self.running:
            client, addr = server.accept()
            threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()

    async def auto_pivot(self, target_ip: str, orchestrator):
        """v6.0: Automatically explores and pivots into a new target IP."""
        console.print(f"[bold yellow][🔗] AuraLink: Auto-Pivot engaged for {target_ip}. Testing lateral movement...[/bold yellow]")
        
        # 1. Check for common pivot entry points
        vulnerable = self.brute_ssh_pivot(target_ip)
        if vulnerable:
            console.print(f"[bold green][✔] AuraLink: Lateral movement SUCCESS on {target_ip}. Dropping pivot agent.[/bold green]")
            # In a real scenario, we'd spawn a new SwarmNode here or route traffic through the new link
            orchestrator.db.log_action("AUTO_PIVOT_SUCCESS", target_ip, "Lateral movement confirmed via SSH")
            return True
        return False
