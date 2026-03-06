"""
Aura v22.0 — Config System (UX Supercharge Step 1)
Single source of truth for all user settings.

Priority order (highest wins):
  1. Environment variables  (e.g. INTIGRITI_TOKEN)
  2. ~/.aura.yml            (user config file)
  3. Built-in defaults

Usage anywhere in Aura:
    from aura.core.config import cfg
    token = cfg.intigriti_token
    platform = cfg.default_platform
"""
import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from rich.console import Console

console = Console()

CONFIG_PATH = Path.home() / ".aura.yml"


@dataclass
class AuraConfig:
    """
    Global Aura configuration. Singleton — import `cfg` directly.
    Fields can be set in ~/.aura.yml or via environment variables.
    """
    # ── Platform Defaults ──────────────────────────────────────────────
    default_platform:      str   = "intigriti"
    default_concurrency:   int   = 5
    auto_screenshot:       bool  = True
    auto_submit:           bool  = False

    # ── API Tokens ─────────────────────────────────────────────────────
    intigriti_token:       str   = ""
    hackerone_user:        str   = ""
    hackerone_token:       str   = ""

    # ── Telegram Notifications ─────────────────────────────────────────
    notify_telegram:       bool  = False
    telegram_bot_token:    str   = ""
    telegram_chat_id:      str   = ""

    # ── Scan Behaviour ─────────────────────────────────────────────────
    stealth_mode:          bool  = False
    rate_limit_base:       float = 0.4   # seconds between requests
    resume_on_crash:       bool  = True

    # ── Watchlist ──────────────────────────────────────────────────────
    watchlist_programs:    list  = field(default_factory=list)

    # ── Internal ───────────────────────────────────────────────────────
    _loaded_from:          str   = field(default="defaults", repr=False, compare=False)


def _load_yaml() -> dict:
    """Reads ~/.aura.yml if it exists, returns dict (empty if not found)."""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                return {str(k): v for k, v in data.items()}
        except Exception as e:
            console.print(f"[yellow][Config] Warning: could not read ~/.aura.yml: {e}[/yellow]")
    return {}


def _load_env() -> dict:
    """Reads environment variable overrides."""
    env_map = {
        "intigriti_token":    "INTIGRITI_TOKEN",
        "hackerone_user":     "HACKERONE_USER",
        "hackerone_token":    "HACKERONE_TOKEN",
        "telegram_bot_token": "TELEGRAM_BOT_TOKEN",
        "telegram_chat_id":   "TELEGRAM_CHAT_ID",
        "default_platform":   "AURA_PLATFORM",
        "auto_submit":        "AURA_AUTO_SUBMIT",
        "stealth_mode":       "AURA_STEALTH",
        "notify_telegram":    "AURA_NOTIFY_TELEGRAM",
    }
    result = {}
    for field_name, env_var in env_map.items():
        val = os.environ.get(env_var)
        if val is not None:
            # Cast booleans
            if val.lower() in ("true", "1", "yes"):
                val = True
            elif val.lower() in ("false", "0", "no"):
                val = False
            result[field_name] = val
    return result


def _build_config() -> AuraConfig:
    """Merges defaults → YAML → env vars and returns AuraConfig."""
    yml  = _load_yaml()
    env  = _load_env()

    cfg = AuraConfig()
    source = "defaults"

    # Apply YAML values
    for k, v in yml.items():
        if hasattr(cfg, k) and not k.startswith("_"):
            setattr(cfg, k, v)
            source = str(CONFIG_PATH)

    # Apply env var overrides (always win)
    for k, v in env.items():
        if hasattr(cfg, k):
            setattr(cfg, k, v)

    cfg._loaded_from = source
    return cfg


def save_config(data: dict) -> None:
    """
    Saves a dict of settings to ~/.aura.yml
    Merges with existing file — does not overwrite untouched keys.
    """
    existing = _load_yaml()
    existing.update(data)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.dump(existing, f, default_flow_style=False, allow_unicode=True)
    console.print(f"[green][Config] Saved to {CONFIG_PATH}[/green]")


# ── Singleton ──────────────────────────────────────────────────────────
# Import this anywhere: `from aura.core.config import cfg`
cfg: AuraConfig = _build_config()
