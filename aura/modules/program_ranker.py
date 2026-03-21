"""
Aura v22.0 — Program Ranker (Tier 1 Intelligence)
Automatically ranks bug bounty programs by earning potential.

Ranking formula:
  score = avg_payout / (avg_response_days + 1) / competition_factor

Usage:
  aura programs                # Show top 20 ranked programs
  aura programs --platform h1  # Filter by platform
  aura programs --new          # Only programs added in last 30 days
"""
import os
import json
import time
import asyncio
from datetime import datetime, timezone, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from aura.ui.formatter import console

CACHE_FILE = os.path.join(os.path.expanduser("~"), ".aura", "programs_cache.json")
CACHE_TTL  = 3600 * 6  # 6 hours


class ProgramRanker:
    """
    Tier 1: Bug Bounty Program Intelligence Engine.
    Pulls live program data from Intigriti and HackerOne APIs,
    ranks them by ROI (payout / response_time / competition).
    """

    def __init__(self):
        try:
            from aura.core.config import cfg
            self.intigriti_token = cfg.intigriti_token or os.environ.get("INTIGRITI_TOKEN", "")
            self.h1_user         = cfg.hackerone_user or os.environ.get("HACKERONE_USER", "")
            self.h1_token        = cfg.hackerone_token or os.environ.get("HACKERONE_TOKEN", "")
        except Exception:
            self.intigriti_token = os.environ.get("INTIGRITI_TOKEN", "")
            self.h1_user         = os.environ.get("HACKERONE_USER", "")
            self.h1_token        = os.environ.get("HACKERONE_TOKEN", "")

    # ─── Data Fetching ───────────────────────────────────────────────────

    async def _fetch_intigriti_programs(self) -> list[dict]:
        """Fetches live programs from Intigriti API using Stealth Mode."""
        if not self.intigriti_token:
            return self._sample_programs("intigriti")
        try:
            from aura.core.stealth import StealthEngine, AuraSession
            stealth = StealthEngine()
            session = AuraSession(stealth)
            
            r = await session.get(
                "https://api.intigriti.com/external/researcher/v1/programs",
                headers={"Authorization": f"Bearer {self.intigriti_token}"},
                timeout=20
            )
            if r and r.status_code == 200:
                data = r.json()
                programs = []
                for p in data.get("records", []):
                    programs.append(self._normalize_intigriti(p))
                return programs
            
            # If we get a real response but it's not 200, log it
            if r:
                console.print(f"[dim yellow][Programs] Intigriti API returned HTTP {r.status_code}[/dim yellow]")
        except Exception as e:
            console.print(f"[dim red][Programs] Intigriti API error: {e}[/dim red]")
        return self._sample_programs("intigriti")

    async def _fetch_hackerone_programs(self) -> list[dict]:
        """Fetches live programs from HackerOne API using Stealth Mode."""
        if not self.h1_user or not self.h1_token:
            return self._sample_programs("hackerone")
        try:
            from aura.core.stealth import StealthEngine, AuraSession
            stealth = StealthEngine()
            session = AuraSession(stealth)
            
            r = await session.get(
                "https://api.hackerone.com/v1/hackers/programs",
                auth=(self.h1_user, self.h1_token),
                params={"page[size]": 100, "filter[offers_bounties]": "true"},
                timeout=20
            )
            if r and r.status_code == 200:
                data = r.json()
                programs = []
                for p in data.get("data", []):
                    programs.append(self._normalize_hackerone(p))
                return programs
            
            if r:
                console.print(f"[dim yellow][Programs] HackerOne API returned HTTP {r.status_code}[/dim yellow]")
        except Exception as e:
            console.print(f"[dim red][Programs] HackerOne API error: {e}[/dim red]")
        return self._sample_programs("hackerone")

    @staticmethod
    def _normalize_intigriti(p: dict) -> dict:
        """Normalizes Intigriti program data."""
        rewards = p.get("maxBounty", {}) or {}
        return {
            "name":           p.get("name", "Unknown"),
            "handle":         p.get("id", ""),
            "platform":       "intigriti",
            "max_bounty":     rewards.get("value", 0),
            "avg_bounty":     rewards.get("value", 0) * 0.4,  # estimate avg as 40% of max
            "response_days":  p.get("averageResponseTime", 7),
            "scope_count":    len(p.get("domains", [])),
            "is_public":      p.get("status", "") == "open",
            "created_at":     p.get("createdAt", ""),
            "url":            f"https://app.intigriti.com/programs/{p.get('id', '')}",
        }

    @staticmethod
    def _normalize_hackerone(p: dict) -> dict:
        """Normalizes HackerOne program data."""
        attrs = p.get("attributes", {})
        stats = attrs.get("statistics", {})
        return {
            "name":           attrs.get("name", "Unknown"),
            "handle":         attrs.get("handle", ""),
            "platform":       "hackerone",
            "max_bounty":     attrs.get("maximum_bounty_table", {}).get("critical", 0) if attrs.get("maximum_bounty_table") else 0,
            "avg_bounty":     stats.get("average_bounty_lower_amount", 0) or 0,
            "response_days":  stats.get("average_time_to_first_response_in_days_last_90_days", 7) or 7,
            "scope_count":    stats.get("resolved_report_count", 0),
            "is_public":      attrs.get("submission_state", "") == "open",
            "created_at":     attrs.get("started_accepting_reports", ""),
            "url":            f"https://hackerone.com/{attrs.get('handle', '')}",
        }

    @staticmethod
    def _sample_programs(platform: str) -> list[dict]:
        """
        Returns well-known high-paying programs as fallback
        when API credentials are not configured.
        """
        programs = [
            # HackerOne high-paying programs
            {"name": "Google VRP", "handle": "google", "platform": "hackerone",
             "max_bounty": 31337, "avg_bounty": 4500, "response_days": 3, "scope_count": 50,
             "is_public": True, "url": "https://hackerone.com/google", "created_at": "2015-01-01"},
            {"name": "Microsoft", "handle": "microsoft", "platform": "hackerone",
             "max_bounty": 30000, "avg_bounty": 3500, "response_days": 5, "scope_count": 80,
             "is_public": True, "url": "https://hackerone.com/microsoft", "created_at": "2014-06-01"},
            {"name": "Phabricator", "handle": "phabricator", "platform": "hackerone",
             "max_bounty": 5000, "avg_bounty": 1200, "response_days": 2, "scope_count": 10,
             "is_public": True, "url": "https://hackerone.com/phabricator", "created_at": "2016-01-01"},
            # Intigriti high-paying programs
            {"name": "Ubisoft", "handle": "ubisoft", "platform": "intigriti",
             "max_bounty": 20000, "avg_bounty": 2000, "response_days": 7, "scope_count": 30,
             "is_public": True, "url": "https://app.intigriti.com/programs/ubisoft", "created_at": "2020-01-01"},
            {"name": "Spotify", "handle": "spotify", "platform": "intigriti",
             "max_bounty": 10000, "avg_bounty": 1500, "response_days": 5, "scope_count": 25,
             "is_public": True, "url": "https://app.intigriti.com/programs/spotify", "created_at": "2021-01-01"},
            {"name": "Legalrobot", "handle": "legalrobot", "platform": "intigriti",
             "max_bounty": 2500, "avg_bounty": 800, "response_days": 2, "scope_count": 8,
             "is_public": True, "url": "https://app.intigriti.com/programs/legalrobot", "created_at": "2022-06-01"},
        ]
        return [p for p in programs if p["platform"] == platform] if platform != "all" else programs

    # ─── Ranking ─────────────────────────────────────────────────────────

    @staticmethod
    def _score(p: dict) -> float:
        """
        ROI Score = avg_bounty / (response_days + 1)
        Higher = more money per day of effort.
        """
        avg    = float(p.get("avg_bounty", 0) or 0)
        days   = float(p.get("response_days", 7) or 7)
        return round(avg / (days + 1), 2)

    def rank(self, programs: list[dict], only_new: bool = False) -> list[dict]:
        """Sorts programs by ROI score, optionally filtering to new ones."""
        if only_new:
            cutoff = datetime.now(timezone.utc) - timedelta(days=30)
            programs = [p for p in programs if self._is_new(p.get("created_at", ""), cutoff)]

        for p in programs:
            p["roi_score"] = self._score(p)
            p["is_new"]    = self._is_new(p.get("created_at", ""), datetime.now(timezone.utc) - timedelta(days=30))

        return sorted(programs, key=lambda p: p["roi_score"], reverse=True)

    @staticmethod
    def _is_new(created_at: str, cutoff: datetime) -> bool:
        """Returns True if the program was created after the cutoff."""
        if not created_at:
            return False
        try:
            ts = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts >= cutoff
        except Exception:
            return False

    # ─── Display ─────────────────────────────────────────────────────────

    @staticmethod
    def print_ranked(programs: list[dict], limit: int = 20):
        """Prints the ranked programs table."""
        table = Table(title="🏆 Top Bug Bounty Programs by ROI", show_header=True, header_style="bold cyan")
        table.add_column("#",        style="dim",       width=4)
        table.add_column("Program",  width=22)
        table.add_column("Platform", width=10)
        table.add_column("Max $",    width=10)
        table.add_column("Avg $",    width=8)
        table.add_column("Resp (d)", width=8)
        table.add_column("ROI",      width=8)
        table.add_column("🆕",       width=3)

        for i, p in enumerate(programs[:limit], 1):
            new_badge = "🔥" if p.get("is_new") else ""
            platform_color = "cyan" if p["platform"] == "intigriti" else "green"
            table.add_row(
                str(i),
                f"[bold]{p['name'][:20]}[/bold]",
                f"[{platform_color}]{p['platform'][:9]}[/{platform_color}]",
                f"${p.get('max_bounty', 0):,}",
                f"${p.get('avg_bounty', 0):,.0f}",
                str(p.get("response_days", "?")),
                f"[yellow]{p.get('roi_score', 0):.1f}[/yellow]",
                new_badge,
            )
        console.print(table)
        console.print("[dim]ROI = Avg Payout ÷ Response Days. Higher = better use of your time.[/dim]")

    # ─── Main Entry ──────────────────────────────────────────────────────

    async def get_ranked_programs(self, platform: str = "all", only_new: bool = False) -> list[dict]:
        """Fetches and ranks programs from all platforms."""
        console.print("[cyan][Programs] Fetching bug bounty programs...[/cyan]")

        if platform == "all":
            intigriti, h1 = await asyncio.gather(
                self._fetch_intigriti_programs(),
                self._fetch_hackerone_programs(),
            )
            programs = intigriti + h1
        elif platform == "intigriti":
            programs = await self._fetch_intigriti_programs()
        else:
            programs = await self._fetch_hackerone_programs()

        ranked = self.rank(programs, only_new=only_new)
        return ranked
