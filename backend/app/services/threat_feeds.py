"""
Local Threat Intelligence Feeds.

Downloads free public IP blocklists and checks IPs locally.
No API keys, no quotas, unlimited checks, microsecond lookups.

Feeds are refreshed on startup and every REFRESH_INTERVAL_SECONDS in a background thread.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set

import requests

logger = logging.getLogger(__name__)

REFRESH_INTERVAL_SECONDS = 6 * 3600  # 6 hours

_IPV4_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})$")
_IPV4_EXTRACT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

FEEDS: List[Dict[str, str]] = [
    {
        "name": "Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "desc": "Botnet C2 servers",
    },
    {
        "name": "URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "desc": "Malware distribution",
        "extract_ips": "true",  # URLs contain embedded IPs
    },
    {
        "name": "Blocklist.de",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "desc": "Brute force, bots, scanners",
    },
    {
        "name": "CI Army",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "desc": "Hostile IPs",
    },
    {
        "name": "Emerging Threats",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "desc": "Compromised IPs",
    },
]


@dataclass(frozen=True)
class ThreatFeedResult:
    found: bool = False
    score: float = 0.0          # 0..100
    sources: str = ""           # comma-separated feed names
    source_count: int = 0


class ThreatFeedStore:
    """Thread-safe in-memory store for all downloaded blocklist IPs."""

    def __init__(self):
        self._lock = threading.Lock()
        self._feeds: Dict[str, FrozenSet[str]] = {}
        self._last_refresh: float = 0.0
        self._total_ips: int = 0
        self._refresh_thread: Optional[threading.Thread] = None
        self._running = False

    def start_background_refresh(self) -> None:
        if self._running:
            return
        self._running = True
        self._refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self._refresh_thread.start()

    def _refresh_loop(self) -> None:
        self.refresh()
        while self._running:
            time.sleep(REFRESH_INTERVAL_SECONDS)
            if self._running:
                self.refresh()

    def refresh(self) -> None:
        logger.info("Threat feeds: starting refresh (%d feeds)...", len(FEEDS))
        new_feeds: Dict[str, FrozenSet[str]] = {}
        total = 0
        for feed in FEEDS:
            name = feed["name"]
            url = feed["url"]
            extract_mode = feed.get("extract_ips") == "true"
            try:
                ips = _download_feed(url, extract_ips=extract_mode)
                new_feeds[name] = frozenset(ips)
                total += len(ips)
                logger.info("  %-20s: %d IPs", name, len(ips))
            except Exception as e:
                logger.warning("  %-20s: FAILED (%s)", name, e)
                with self._lock:
                    if name in self._feeds:
                        new_feeds[name] = self._feeds[name]
                        total += len(self._feeds[name])

        with self._lock:
            self._feeds = new_feeds
            self._total_ips = total
            self._last_refresh = time.time()
        logger.info("Threat feeds: refresh complete — %d unique IPs across %d feeds", total, len(new_feeds))

    def check(self, ip: str) -> ThreatFeedResult:
        ip = (ip or "").strip()
        if not ip:
            return ThreatFeedResult()

        with self._lock:
            feeds_snapshot = dict(self._feeds)

        matched: List[str] = []
        for name, ip_set in feeds_snapshot.items():
            if ip in ip_set:
                matched.append(name)

        if not matched:
            return ThreatFeedResult()

        n = len(matched)
        if n >= 3:
            score = 90.0
        elif n >= 2:
            score = 70.0
        else:
            score = 40.0

        return ThreatFeedResult(
            found=True,
            score=score,
            sources=", ".join(matched),
            source_count=n,
        )

    def get_status(self) -> Dict:
        with self._lock:
            return {
                "total_ips": self._total_ips,
                "feeds_loaded": len(self._feeds),
                "feed_details": {name: len(ips) for name, ips in self._feeds.items()},
                "last_refresh": self._last_refresh,
                "last_refresh_ago_s": int(time.time() - self._last_refresh) if self._last_refresh else None,
            }


def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _download_feed(url: str, timeout: int = 30, extract_ips: bool = False) -> Set[str]:
    resp = requests.get(url, timeout=timeout, headers={"User-Agent": "NetGuard-ThreatFeed/1.0"})
    resp.raise_for_status()

    ips: Set[str] = set()
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if extract_ips:
            for m in _IPV4_EXTRACT_RE.finditer(line):
                candidate = m.group(1)
                if _is_valid_ipv4(candidate):
                    ips.add(candidate)
        else:
            m = _IPV4_RE.match(line)
            if m and _is_valid_ipv4(m.group(1)):
                ips.add(m.group(1))
    # Filter out non-routable addresses that aren't useful for threat matching
    ips.discard("0.0.0.0")
    ips.discard("127.0.0.1")
    return ips


# Global singleton
threat_feed_store = ThreatFeedStore()
