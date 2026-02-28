import os
import requests
from rich.console import Console

console = Console()

class CommLink:
    """Handles real-time notifications for critical findings."""
    
    def __init__(self):
        self.telegram_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID")
        
    def send_telegram_alert(self, message):
        """Send an alert to Telegram if configured."""
        if not self.telegram_token or not self.telegram_chat_id:
            return False
            
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": f"🚨 *AURA VANGUARD ALERT* 🚨\n{message}",
            "parse_mode": "Markdown"
        }
        try:
            response = requests.post(url, json=payload, timeout=5)
            if response.status_code == 200:
                console.print("[dim cyan][*] Alert dispatched via Comm-Link.[/dim cyan]")
                return True
        except Exception as e:
            console.print(f"[dim red][!] Comm-Link dispatch failed: {e}[/dim red]")
        return False
