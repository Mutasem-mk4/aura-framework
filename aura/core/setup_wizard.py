"""
Aura v22.X — Setup Wizard (UX Supercharge + Beginner Mode)
Interactive first-time setup — prompts for API tokens, tests them live,
writes ~/.aura.yml on success.

Run once:
    aura setup
"""
import asyncio
import os
import click
from rich.console import Console
from rich.panel import Panel
from aura.core.config import save_config, CONFIG_PATH

console = Console()

# ── API Key Testing Functions ─────────────────────────────────────────

async def _test_shodan(key: str) -> tuple[bool, str]:
    """Test Shodan API key."""
    if not key:
        return False, "No key provided"
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://api.shodan.io/shodan/host/1.1.1.1?key={key}",
                timeout=10
            ) as resp:
                if resp.status == 200:
                    return True, "Shodan API active"
                elif resp.status == 403:
                    return False, "Invalid API key"
                return False, f"HTTP {resp.status}"
    except Exception as e:
        return False, str(e)

async def _test_virustotal(key: str) -> tuple[bool, str]:
    """Test VirusTotal API key."""
    if not key:
        return False, "No key provided"
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1",
                headers={"x-apikey": key},
                timeout=10
            ) as resp:
                if resp.status == 200:
                    return True, "VirusTotal API active"
                elif resp.status == 401:
                    return False, "Invalid API key"
                return False, f"HTTP {resp.status}"
    except Exception as e:
        return False, str(e)

async def _test_otx(key: str) -> tuple[bool, str]:
    """Test AlienVault OTX API key."""
    if not key:
        return False, "No key provided"
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://otx.alienvault.com/api/v1/user/me",
                headers={"X-OTX-API-KEY": key},
                timeout=10
            ) as resp:
                if resp.status == 200:
                    return True, "OTX API active"
                elif resp.status == 403:
                    return False, "Invalid API key"
                return False, f"HTTP {resp.status}"
    except Exception as e:
        return False, str(e)

async def _test_censys(api_id: str, api_secret: str) -> tuple[bool, str]:
    """Test Censys API credentials."""
    if not api_id or not api_secret:
        return False, "No credentials provided"
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://search.censys.io/api/v1/account",
                auth=aiohttp.BasicAuth(api_id, api_secret),
                timeout=10
            ) as resp:
                if resp.status == 200:
                    return True, "Censys API active"
                return False, f"HTTP {resp.status}"
    except Exception as e:
        return False, str(e)

async def _test_hunterio(key: str) -> tuple[bool, str]:
    """Test Hunter.io API key."""
    if not key:
        return False, "No key provided"
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://api.hunter.io/v2/account?api_key={key}",
                timeout=10
            ) as resp:
                if resp.status == 200:
                    return True, "Hunter.io API active"
                return False, f"HTTP {resp.status}"
    except Exception as e:
        return False, str(e)

async def _test_greynoise(key: str) -> tuple[bool, str]:
    """Test GreyNoise API key."""
    if not key:
        return False, "No key provided"
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.greynoise.io/v3/community/1.1.1.1",
                headers={"key": key},
                timeout=10
            ) as resp:
                if resp.status == 200:
                    return True, "GreyNoise API active"
                return False, f"HTTP {resp.status}"
    except Exception as e:
        return False, str(e)


# ── API Key Configuration Data ─────────────────────────────────────────

API_KEYS = [
    {
        "name": "Shodan",
        "env_var": "SHODAN_API_KEY",
        "url": "https://shodan.io/profile/api",
        "free_tier": "Free tier: 1M credits/month",
        "test_func": _test_shodan,
    },
    {
        "name": "VirusTotal",
        "env_var": "VIRUSTOTAL_API_KEY",
        "url": "https://virustotal.com/gui/home/search",
        "free_tier": "Free tier: 4 lookups/minute",
        "test_func": _test_virustotal,
    },
    {
        "name": "AlienVault OTX",
        "env_var": "OTX_API_KEY",
        "url": "https://otx.alienvault.com/api",
        "free_tier": "Free tier: 1000 pulses/day",
        "test_func": _test_otx,
    },
    {
        "name": "Censys",
        "env_var_id": "CENSYS_API_ID",
        "env_var_secret": "CENSYS_API_SECRET",
        "url": "https://censys.io/account/api",
        "free_tier": "Free tier: 10 queries/day",
        "test_func": _test_censys,
        "has_id_and_secret": True,
    },
    {
        "name": "Hunter.io",
        "env_var": "HUNTERIO_API_KEY",
        "url": "https://hunter.io/users/sign_up",
        "free_tier": "Free tier: 25 searches/month",
        "test_func": _test_hunterio,
    },
    {
        "name": "GreyNoise",
        "env_var": "GREYNOISE_API_KEY",
        "url": "https://greynoise.io/account/settings",
        "free_tier": "Free tier: Community tier available",
        "test_func": _test_greynoise,
    },
]


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
            headers={"Authorization": f"Base {auth_base64}"},
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


def _detect_missing_keys() -> list:
    """Detect which API keys are missing from environment."""
    missing = []
    for key_config in API_KEYS:
        if key_config.get("has_id_and_secret"):
            if not os.environ.get(key_config["env_var_id"]) or not os.environ.get(key_config["env_var_secret"]):
                missing.append(key_config)
        else:
            if not os.environ.get(key_config["env_var"]):
                missing.append(key_config)
    return missing


def run_wizard():
    """
    Interactive setup wizard. Call from CLI: aura setup
    Steps through beginner mode, platform selection, API tokens, OSINT keys, and Telegram config.
    """
    console.print(Panel(
        "[bold cyan]Welcome to Aura Setup Wizard (v22.X)[/bold cyan]\n"
        "This will configure your API tokens, beginner mode, and preferences.\n"
        f"Settings will be saved to [yellow]{CONFIG_PATH}[/yellow]",
        title="[bold yellow]🧙 Aura Setup[/bold yellow]",
        border_style="cyan"
    ))

    new_config = {}

    # ── Step 0: Beginner Mode ─────────────────────────────────────────
    console.print("\n[bold][NEW] Beginner Mode[/bold]")
    console.print("  Beginner mode provides:")
    console.print("  - Educational tips after each scan")
    console.print("  - Plain-English vulnerability explanations")
    console.print("  - Practice mode with safe targets")
    console.print("  - Guided hunt -> learn -> exploit workflow")
    beginner_mode = click.confirm("  Enable beginner mode?", default=True)
    new_config["beginner_mode"] = beginner_mode
    if beginner_mode:
        console.print("  [green]✅ Beginner mode enabled[/green]")
    else:
        console.print("  [dim]Beginner mode disabled[/dim]")

    # ── Step 1: Default Platform ───────────────────────────────────────
    console.print("\n[bold][1/6] Default Platform[/bold]")
    platform = click.prompt(
        "  Choose platform",
        type=click.Choice(["intigriti", "hackerone", "bugcrowd"]),
        default="intigriti",
        show_default=True,
    )
    new_config["default_platform"] = platform
    console.print(f"  [green]✅ Platform set to: {platform}[/green]")

    # ── Step 2: Intigriti Token ────────────────────────────────────────
    console.print("\n[bold][2/6] Intigriti API Token[/bold]")
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
    console.print("\n[bold][3/6] HackerOne Credentials[/bold]")
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

    # ── Step 4: OSINT API Keys (Auto-detect + Setup) ─────────────────
    console.print("\n[bold][4/6] OSINT API Keys (Optional)[/bold]")
    missing_keys = _detect_missing_keys()
    if missing_keys:
        console.print(f"  [yellow]Found {len(missing_keys)} missing API keys[/yellow]")
        console.print("  These improve reconnaissance quality but are optional.\n")

        setup_all = click.confirm("  Setup all missing API keys now?", default=True)
        if setup_all:
            for key_config in missing_keys:
                console.print(f"\n  [bold]--- {key_config['name']} ---[/bold]")
                console.print(f"  {key_config['free_tier']}")
                console.print(f"  Get your key at: [cyan]{key_config['url']}[/cyan]")

                if key_config.get("has_id_and_secret"):
                    api_id = click.prompt("  API ID", default="", hide_input=True)
                    api_secret = click.prompt("  API Secret", default="", hide_input=True)
                    if api_id and api_secret:
                        console.print("  [yellow]Testing...[/yellow]", end=" ")
                        ok, info = asyncio.get_event_loop().run_until_complete(
                            key_config["test_func"](api_id, api_secret)
                        )
                        if ok:
                            console.print(f"[bold green]✅ {info}[/bold green]")
                            os.environ[key_config["env_var_id"]] = api_id
                            os.environ[key_config["env_var_secret"]] = api_secret
                        else:
                            console.print(f"[red]❌ Failed: {info}[/red]")
                else:
                    api_key = click.prompt("  API Key", default="", hide_input=True)
                    if api_key:
                        console.print("  [yellow]Testing...[/yellow]", end=" ")
                        ok, info = asyncio.get_event_loop().run_until_complete(
                            key_config["test_func"](api_key)
                        )
                        if ok:
                            console.print(f"[bold green]✅ {info}[/bold green]")
                            os.environ[key_config["env_var"]] = api_key
                        else:
                            console.print(f"[red]❌ Failed: {info}[/red]")
    else:
        console.print("  [green]✅ All OSINT API keys already configured[/green]")

    # ── Step 5: Scan Preferences ───────────────────────────────────────
    console.print("\n[bold][5/6] Scan Preferences[/bold]")
    concurrency = click.prompt("  Max parallel targets", default=5, type=int)
    auto_ss     = click.confirm("  Auto-screenshot confirmed findings?", default=True)
    auto_sub    = click.confirm("  Auto-submit top finding after scan?", default=False)
    new_config["default_concurrency"] = concurrency
    new_config["auto_screenshot"]     = auto_ss
    new_config["auto_submit"]         = auto_sub
    console.print(f"  [green]✅ Concurrency: {concurrency} | Screenshot: {auto_ss} | Auto-submit: {auto_sub}[/green]")

    # ── Step 6: Telegram ───────────────────────────────────────────────
    console.print("\n[bold][6/6] Telegram Notifications[/bold]")
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

    # Show beginner mode tips
    if new_config.get("beginner_mode"):
        console.print(Panel(
            "[bold green]✅ Beginner Mode Enabled![/bold green]\n\n"
            "New commands available:\n"
            "  [cyan]aura practice --list[/cyan]    — list safe practice targets\n"
            "  [cyan]aura learn xss[/cyan]         — learn about a vulnerability\n"
            "  [cyan]aura hunt target.com[/cyan]   — guided hunt -> learn -> exploit\n",
            title="[bold yellow]🎓 Beginner Tips[/bold yellow]",
            border_style="green"
        ))

    console.print(Panel(
        f"[bold green]✅ Setup Complete![/bold green]\n\n"
        f"Config saved to: [yellow]{CONFIG_PATH}[/yellow]\n\n"
        f"[bold]Try these commands:[/bold]\n"
        f"  [cyan]aura status[/cyan]          — see your dashboard\n"
        f"  [cyan]aura programs[/cyan]        — top bounty programs\n"
        f"  [cyan]aura practice --list[/cyan] — practice on safe targets (beginner mode)\n"
        f"  [cyan]aura hunt ubisoft.com[/cyan] — start hunting!",
        title="[bold yellow]🚀 Ready to Hunt[/bold yellow]",
        border_style="green"
    ))
