"""
Aura v2 — Burp Suite XML Import Module
=========================================
Turn your Burp Suite HTTP history into an Aura discovery map instantly.

Workflow:
  1. In Burp Suite: Proxy → HTTP History → Select All → Right-click → Save Items → burp_export.xml
  2. Run: aura www.target.com --burp burp_export.xml
  3. Aura converts all authenticated requests to a discovery_map.json
  4. Then run: aura www.target.com --hunt  (uses the new discovery map)
  5. Then run: aura --report reports/bola_findings_*.json  (AI report)

This is the 10x productivity multiplier — you browse for 10 minutes
and Aura tests 500 endpoints automatically overnight.
"""

import base64
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional


# ─── Constants ─────────────────────────────────────────────────────────────────
UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
NUMERIC_ID_RE = re.compile(r'/(\d{3,})')

SKIP_EXTENSIONS = re.compile(
    r'\.(css|js|png|jpg|gif|svg|woff|woff2|ico|ttf|otf|map|webp)(\?.*)?$',
    re.IGNORECASE
)
SKIP_HOSTS = re.compile(
    r'(google-analytics|doubleclick|facebook|contentsquare|datadoghq'
    r'|cookielaw|hotjar|segment\.io|amplitude|mixpanel|useinsider)',
    re.IGNORECASE
)

MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Keywords that indicate interesting/sensitive API endpoints
HIGH_VALUE_PATTERNS = re.compile(
    r'(/api/|/v\d+/|/rest/|/graphql|/user|/account|/profile|/cart|'
    r'/order|/address|/payment|/wish|/admin|/manage)',
    re.IGNORECASE
)


class BurpXMLReader:
    """
    Parses a Burp Suite HTTP history XML export and converts it
    into Aura's discovery_map.json format for BOLA testing.
    """

    def __init__(
        self,
        target_filter: Optional[str] = None,
        output_dir: str = "./reports",
    ):
        """
        Args:
            target_filter: If set, only include requests to this domain.
            output_dir: Where to save the generated discovery map.
        """
        self.target_filter = target_filter.lower().replace("www.", "") if target_filter else None
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.all_requests: list[dict] = []
        self.api_calls: list[dict] = []

    @staticmethod
    def _decode(text: Optional[str], is_base64: bool) -> str:
        """Decode a Burp field that may be base64-encoded."""
        if not text:
            return ""
        if is_base64:
            try:
                return base64.b64decode(text).decode("utf-8", errors="replace")
            except Exception:
                return text
        return text

    def _extract_ids(self, url: str) -> list[dict]:
        """Extracts UUIDs and numeric IDs from a URL."""
        ids_found = []
        for uid in UUID_RE.findall(url):
            ids_found.append({"type": "uuid", "value": uid})
        for nid in NUMERIC_ID_RE.findall(url):
            ids_found.append({"type": "numeric", "value": nid})
        return ids_found

    def _is_interesting(self, url: str, method: str) -> bool:
        """Decides if a request is interesting enough to include."""
        if SKIP_EXTENSIONS.search(url):
            return False
        if SKIP_HOSTS.search(url):
            return False
        # Always include mutating methods
        if method in MUTATING_METHODS:
            return True
        # Include GET/HEAD only if they match API or account patterns
        return bool(HIGH_VALUE_PATTERNS.search(url))

    def _is_target_host(self, host: str) -> bool:
        """Checks if a request matches the target filter."""
        if not self.target_filter:
            return True
        host_clean = host.lower().replace("www.", "")
        return self.target_filter in host_clean

    def parse(self, xml_path: str) -> dict:
        """
        Parses a Burp XML export file and returns a discovery map dict.
        """
        xml_path = Path(xml_path)
        if not xml_path.exists():
            print(f"❌ Burp XML file not found: {xml_path}")
            return {}

        print(f"\n{'='*65}")
        print(f"📊 AURA v2 — Burp Suite XML Importer")
        print(f"📁 File: {xml_path}")
        if self.target_filter:
            print(f"🎯 Filtering to: *.{self.target_filter}.*")
        print(f"{'='*65}")

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except ET.ParseError as e:
            print(f"❌ Failed to parse XML: {e}")
            return {}

        items = root.findall("item")
        print(f"📋 Total items in export: {len(items)}")

        for item in items:
            try:
                host = (item.findtext("host") or "").strip()
                url = (item.findtext("url") or "").strip()
                method = (item.findtext("method") or "GET").strip().upper()
                status_str = item.findtext("status") or "0"
                status = int(status_str) if status_str.isdigit() else 0

                # Handle base64-encoded request body
                req_elem = item.find("request")
                req_b64 = req_elem.get("base64", "false").lower() == "true" if req_elem is not None else False
                raw_request = self._decode(req_elem.text if req_elem is not None else None, req_b64)

                # Extract post data from request body
                post_data = None
                if "\r\n\r\n" in raw_request:
                    post_data = raw_request.split("\r\n\r\n", 1)[-1].strip() or None
                elif "\n\n" in raw_request:
                    post_data = raw_request.split("\n\n", 1)[-1].strip() or None

                # Extract Cookie header from raw request
                cookies_header = ""
                for line in raw_request.splitlines():
                    if line.lower().startswith("cookie:"):
                        cookies_header = line[7:].strip()
                        break

                self.all_requests.append({
                    "host": host,
                    "url": url,
                    "method": method,
                    "status": status,
                    "post_data": post_data,
                    "cookies_header": cookies_header,
                })

            except Exception as e:
                continue  # Skip malformed items

        # Filter to interesting, target-matching requests
        seen = set()
        for req in self.all_requests:
            url = req["url"]
            method = req["method"]
            host = req["host"]

            if not self._is_target_host(host):
                continue
            if not self._is_interesting(url, method):
                continue

            dedup_key = f"{method}:{url}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            ids = self._extract_ids(url)
            self.api_calls.append({
                "url": url,
                "method": method,
                "ids_found": ids,
                "post_data": req["post_data"],
                "is_mutating": method in MUTATING_METHODS,
                "has_ids": len(ids) > 0,
                "source": "burp_import",
                "original_status": req["status"],
            })

        # Build & save the discovery map
        discovery_map = self._build_discovery_map()
        self._save_discovery_map(discovery_map)
        self._print_summary(discovery_map)
        return discovery_map

    def _build_discovery_map(self) -> dict:
        """Organizes parsed API calls into a discovery map."""
        mutating = [c for c in self.api_calls if c["is_mutating"]]
        idor_candidates = [c for c in self.api_calls if c["has_ids"]]

        return {
            "meta": {
                "target": self.target_filter or "all",
                "source": "burp_xml_import",
                "scan_time": datetime.utcnow().isoformat(),
                "total_api_calls": len(self.api_calls),
                "mutating_endpoints": len(mutating),
                "idor_candidates": len(idor_candidates),
                "pages_visited": 0,
            },
            "idor_candidates": [
                {
                    "url": c["url"],
                    "method": c["method"],
                    "ids": c["ids_found"],
                    "source_page": "burp_import",
                    "post_data": c["post_data"],
                }
                for c in idor_candidates
            ],
            "mutating_endpoints": [
                {
                    "url": c["url"],
                    "method": c["method"],
                    "source_page": "burp_import",
                    "post_data": c["post_data"],
                    "headers": {},
                }
                for c in mutating
            ],
            "all_api_calls": self.api_calls,
        }

    def _save_discovery_map(self, discovery_map: dict):
        """Saves the discovery map to the reports directory."""
        target_slug = (self.target_filter or "burp_import").replace(".", "_")
        output_path = self.output_dir / f"discovery_map_{target_slug}.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(discovery_map, f, indent=2)
        print(f"\n💾 Discovery map saved: {output_path}")

    def _print_summary(self, discovery_map: dict):
        """Prints a human-readable summary."""
        meta = discovery_map["meta"]
        print(f"\n{'='*65}")
        print(f"✅ BURP IMPORT COMPLETE")
        print(f"{'='*65}")
        print(f"  📊 Total Relevant API Calls : {meta['total_api_calls']}")
        print(f"  🔥 Mutating (POST/PATCH/DELETE) : {meta['mutating_endpoints']}")
        print(f"  🎯 IDOR Candidates (IDs in URL) : {meta['idor_candidates']}")

        if discovery_map["idor_candidates"]:
            print(f"\n🚨 TOP IDOR CANDIDATES FROM BURP:")
            for ep in discovery_map["idor_candidates"][:8]:
                ids_str = ", ".join([
                    f"{i['type']}:{i['value'][:10]}..."
                    for i in ep["ids"]
                ])
                print(f"  [{ep['method']}] {ep['url'][:80]}")
                print(f"       IDs: {ids_str}")
        
        print(f"\n💡 Next step: aura <target> --hunt")
        print(f"{'='*65}\n")


def run_burp_import(
    xml_path: str,
    target: Optional[str] = None,
    output_dir: str = "./reports"
) -> dict:
    """CLI runner for `aura <target> --burp <file.xml>`."""
    reader = BurpXMLReader(
        target_filter=target,
        output_dir=output_dir,
    )
    return reader.parse(xml_path)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m aura.modules.burp_reader <burp_export.xml> [target_domain]")
        sys.exit(1)

    xml_file = sys.argv[1]
    target_domain = sys.argv[2] if len(sys.argv) > 2 else None
    run_burp_import(xml_file, target=target_domain)
