"""
Aura v22.0 — Setup Wizard (UX Supercharge Step 2)
Interactive first-time setup — prompts for API tokens, tests them live,
writes ~/.aura.yml on success.

Run once:
    aura setup
"""
import asyncio
import click
from rich.console import Console
from rich.panel import Panel
from aura.core.config import save_config, CONFIG_PATH

from aura.ui.formatter import console


async def _test_intigriti(token: str) -> tuple[bool, str]:
    """Tests Intigriti token using Stealth Mode to bypass Cloudflare."""
    if not token:
        return False, "No token provided"
    try:
        from aura.core.stealth import StealthEngine, AuraSession
        stealth = StealthEngine()
        session = AuraSession(stealth)
        
        r = await session.get(
            "https://api.intigriti.com/external/researcher/v1/me",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15
        )
        if r and r.status_code == 200:
            data = r.json()
            name = data.get("userName") or data.get("email") or "researcher"
            return True, name
        
        status = r.status_code if r else "Timeout"
        if status == 403:
            return False, "WAF Blocked or Unauthorized (403)"
        elif status == 401:
            return False, "Invalid Token (401)"
        return False, f"HTTP {status}"
    except Exception as e:
        return False, str(e)


async def _test_hackerone(user: str, token: str) -> tuple[bool, str]:
    """Tests HackerOne credentials using Stealth Mode."""
    if not user or not token:
        return False, "No credentials provided"
    try:
        from aura.core.stealth import StealthEngine, AuraSession
        stealth = StealthEngine()
        session = AuraSession(stealth)
        
        # H1 uses Basic Auth
        import base64
        auth_bytes = f"{user}:{token}".encode("ascii")
        auth_base64 = base64.b64encode(auth_bytes).decode("ascii")
        
        r = await session.get(
            "https://api.hackerone.com/v1/hackers/me",
            headers={"Authorization": f"Base {auth_base64}"}, # curl_cffi needs manual auth header in some versions or auth tuple
            # Wait, let's use standard auth if curl_cffi supports it in AuraSession.request
            timeout=15,
            auth=(user, token) 
        )
        if r and r.status_code == 200:
            data = r.json()
            name = data.get("data", {}).get("attributes", {}).get("username", user)
            return True, name
        
        status = r.status_code if r else "Timeout"
        return False, f"HTTP {status}"
    except Exception as e:
        return False, str(e)


async def _test_telegram(bot_token: str, chat_id: str) -> bool:
    """Sends a test Telegram message. Returns True on success."""
    try:
        from aura.core.notifier import TelegramNotifier
        n = TelegramNotifier(bot_token=bot_token, chat_id=chat_id)
        n.enabled = bool(bot_token) and bool(chat_id)
        return await n.test()
    except Exception:
        return False


def run_wizard():
    """
    Interactive setup wizard. Call from CLI: aura setup
    Steps through platform selection, API tokens, and Telegram config.
    """
    console.print(Panel(
        "[bold cyan]Welcome to Aura Setup Wizard[/bold cyan]\n"
        "This will configure your API tokens and preferences.\n"
        f"Settings will be saved to [yellow]{CONFIG_PATH}[/yellow]",
        title="[bold yellow]🧙 Aura Setup[/bold yellow]",
        border_style="cyan"
    ))

    new_config = {}

    # ── Step 1: Default Platform ───────────────────────────────────────
    console.print("\n[bold][1/5] Default Platform[/bold]")
    platform = click.prompt(
        "  Choose platform",
        type=click.Choice(["intigriti", "hackerone", "bugcrowd"]),
        default="intigriti",
        show_default=True,
    )
    new_config["default_platform"] = platform
    console.print(f"  [green]✅ Platform set to: {platform}[/green]")

    # ── Step 2: Intigriti Token ────────────────────────────────────────
    console.print("\n[bold][2/5] Intigriti API Token[/bold]")
    console.print("  Get yours at: [cyan]https://app.intigriti.com/researcher/profile/api[/cyan]")
    inti_token = click.prompt("  Token", default="", show_default=False, hide_input=True)
    if inti_token:
        console.print("  [yellow]Testing...[/yellow]", end=" ")
        ok, info = asyncio.get_event_loop().run_until_complete(_test_intigriti(inti_token))
        if ok:
            console.print(f"[bold green]✅ Connected as {info}[/bold green]")
            new_config["intigriti_token"] = inti_token
        else:
            console.print(f"[red]❌ Failed: {info}[/red] (saved anyway)")
            new_config["intigriti_token"] = inti_token
    else:
        console.print("  [dim]Skipped[/dim]")

    # ── Step 3: HackerOne Credentials ─────────────────────────────────
    console.print("\n[bold][3/5] HackerOne Credentials[/bold]")
    console.print("  Get yours at: [cyan]https://hackerone.com/settings/api_token/edit[/cyan]")
    h1_user  = click.prompt("  HackerOne username", default="", show_default=False)
    h1_token = click.prompt("  HackerOne API token", default="", show_default=False, hide_input=True)
    if h1_user and h1_token:
        console.print("  [yellow]Testing...[/yellow]", end=" ")
        ok, info = asyncio.get_event_loop().run_until_complete(_test_hackerone(h1_user, h1_token))
        if ok:
            console.print(f"[bold green]✅ Connected as @{info}[/bold green]")
        else:
            console.print(f"[red]❌ Failed: {info}[/red] (saved anyway)")
        new_config["hackerone_user"]  = h1_user
        new_config["hackerone_token"] = h1_token
    else:
        console.print("  [dim]Skipped[/dim]")

    # ── Step 4: Scan Preferences ───────────────────────────────────────
    console.print("\n[bold][4/5] Scan Preferences[/bold]")
    concurrency = click.prompt("  Max parallel targets", default=5, type=int)
    auto_ss     = click.confirm("  Auto-screenshot confirmed findings?", default=True)
    auto_sub    = click.confirm("  Auto-submit top finding after scan?", default=False)
    new_config["default_concurrency"] = concurrency
    new_config["auto_screenshot"]     = auto_ss
    new_config["auto_submit"]         = auto_sub
    console.print(f"  [green]✅ Concurrency: {concurrency} | Screenshot: {auto_ss} | Auto-submit: {auto_sub}[/green]")

    # ── Step 5: Telegram ───────────────────────────────────────────────
    console.print("\n[bold][5/5] Telegram Notifications[/bold]")
    enable_tg = click.confirm("  Enable Telegram notifications?", default=False)
    if enable_tg:
        console.print("  Create a bot at: [cyan]https://t.me/BotFather[/cyan]")
        console.print("  Get your chat ID at: [cyan]https://t.me/userinfobot[/cyan]")
        tg_token   = click.prompt("  Bot token", hide_input=True)
        tg_chat_id = click.prompt("  Chat ID")
        console.print("  [yellow]Sending test message...[/yellow]", end=" ")
        ok = asyncio.get_event_loop().run_until_complete(_test_telegram(tg_token, tg_chat_id))
        if ok:
            console.print("[bold green]✅ Test message sent![/bold green]")
            new_config["notify_telegram"]    = True
            new_config["telegram_bot_token"] = tg_token
            new_config["telegram_chat_id"]   = tg_chat_id
        else:
            console.print("[red]❌ Failed — check token and chat ID[/red]")
            if click.confirm("  Save anyway?", default=False):
                new_config["notify_telegram"]    = True
                new_config["telegram_bot_token"] = tg_token
                new_config["telegram_chat_id"]   = tg_chat_id
    else:
        console.print("  [dim]Skipped[/dim]")

    # ── Save ───────────────────────────────────────────────────────────
    console.print()
    save_config(new_config)

    console.print(Panel(
        f"[bold green]✅ Setup Complete![/bold green]\n\n"
        f"Config saved to: [yellow]{CONFIG_PATH}[/yellow]\n\n"
        f"[bold]Try these commands:[/bold]\n"
        f"  [cyan]aura status[/cyan]          — see your dashboard\n"
        f"  [cyan]aura programs[/cyan]        — top bounty programs\n"
        f"  [cyan]aura hunt ubisoft.com[/cyan] — start hunting!",
        title="[bold yellow]🚀 Ready to Hunt[/bold yellow]",
        border_style="green"
    ))
