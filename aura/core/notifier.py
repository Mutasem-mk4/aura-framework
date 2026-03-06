"""
Aura v22.0 — Telegram + Desktop Notifier (UX Supercharge Step 5)
Sends notifications when scans complete, findings confirmed, bounties awarded.

Setup (once, via aura setup):
    telegram_bot_token: "7123456:AAxxxxxx"
    telegram_chat_id:   "123456789"

Usage:
    from aura.core.notifier import notify
    await notify.scan_complete("ubisoft.com", findings=7, critical=1)
    await notify.bounty_awarded("ubisoft", amount=1200, currency="USD")
"""
import asyncio
import os
from datetime import datetime, timezone
from rich.console import Console

console = Console()


class TelegramNotifier:
    """
    Sends Telegram Bot API messages for key Aura events.
    Non-blocking — all sends are fire-and-forget (errors are silently logged).
    """

    BOT_API = "https://api.telegram.org/bot{token}/sendMessage"

    def __init__(self, bot_token: str = "", chat_id: str = ""):
        try:
            from aura.core.config import cfg
            self.bot_token = bot_token or cfg.telegram_bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
            self.chat_id   = chat_id   or cfg.telegram_chat_id   or os.environ.get("TELEGRAM_CHAT_ID", "")
            self.enabled   = cfg.notify_telegram and bool(self.bot_token) and bool(self.chat_id)
        except Exception:
            self.bot_token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
            self.chat_id   = chat_id   or os.environ.get("TELEGRAM_CHAT_ID", "")
            self.enabled   = bool(self.bot_token) and bool(self.chat_id)

    async def _send(self, text: str) -> bool:
        if not self.enabled:
            return False
        try:
            import httpx
            url = self.BOT_API.format(token=self.bot_token)
            async with httpx.AsyncClient(timeout=8) as c:
                r = await c.post(url, json={"chat_id": self.chat_id, "text": text, "parse_mode": "HTML"})
                if r.status_code != 200:
                    console.print(f"[dim red][Notifier] Telegram API error: {r.status_code} - {r.text[:100]}[/dim red]")
                return r.status_code == 200
        except Exception as e:
            console.print(f"[dim red][Notifier] Telegram send failed: {e}[/dim red]")
            return False

    async def test(self) -> bool:
        ts  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        ok  = await self._send(f"🟢 <b>Aura Connected</b>\nSetup successful at {ts}")
        if ok:
            console.print("[green][Notifier] Telegram test message sent ✅[/green]")
        else:
            console.print("[red][Notifier] Telegram test failed — check token/chat_id[/red]")
        return ok

    async def scan_complete(self, target: str, findings: int = 0,
                            critical: int = 0, submitted: bool = False) -> None:
        icon = "🚨" if critical > 0 else ("⚠️" if findings > 0 else "✅")
        text = (
            f"{icon} <b>Scan Complete</b>\n🎯 <code>{target}</code>\n"
            f"📋 Findings: <b>{findings}</b>"
            + (f" ({critical} CRITICAL)" if critical else "")
            + ("\n📤 Auto-submitted" if submitted else "")
            + f"\n🕐 {datetime.now(timezone.utc).strftime('%H:%M UTC')}"
        )
        await self._send(text)

    async def finding_confirmed(self, vuln_type: str, severity: str,
                                target: str, cvss: float = 0.0) -> None:
        if severity.upper() not in ("CRITICAL", "EXCEPTIONAL", "HIGH"):
            return
        icon = "🔴" if severity.upper() in ("CRITICAL", "EXCEPTIONAL") else "🟠"
        text = (
            f"{icon} <b>{severity.upper()} Finding Confirmed!</b>\n"
            f"🔍 <code>{vuln_type}</code>\n🎯 <code>{target}</code>\n📊 CVSS: {cvss}"
        )
        await self._send(text)

    async def bounty_awarded(self, program: str, amount: float,
                             currency: str = "USD", report_id: str = "") -> None:
        text = (
            f"💰 <b>BOUNTY AWARDED!</b>\n🏆 Program: <b>{program}</b>\n"
            f"💵 Amount: <b>${amount:,.0f} {currency}</b>"
            + (f"\n📋 Report: #{report_id}" if report_id else "")
            + f"\n🕐 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        )
        await self._send(text)

    async def submission_status(self, report_id: str, status: str,
                                program: str = "") -> None:
        icons = {"TRIAGED": "🔵", "ACCEPTED": "🟢", "PAID": "💰", "REJECTED": "🔴", "DUPLICATE": "🟡"}
        icon  = icons.get(status.upper(), "📋")
        text  = (
            f"{icon} <b>Report {status.upper()}</b>\n📋 #{report_id}"
            + (f" — {program}" if program else "")
        )
        await self._send(text)

    def fire_and_forget(self, coro) -> None:
        """Runs a notification coroutine without blocking."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(coro)
            else:
                loop.run_until_complete(coro)
        except Exception:
            pass


# ── Singleton ──────────────────────────────────────────────────────────
notify = TelegramNotifier()


class CommLink:
    """
    Backward-compatibility shim. Legacy code used CommLink; it now delegates
    to the TelegramNotifier singleton.
    """
    def send_telegram_alert(self, message: str) -> None:
        """Sends a plain-text Telegram alert (fire-and-forget)."""
        notify.fire_and_forget(notify._send(message))

    def __getattr__(self, name):
        # Silently ignore any other legacy CommLink method calls
        return lambda *a, **kw: None
