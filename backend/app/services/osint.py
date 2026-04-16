from __future__ import annotations

import time
import json
import ipaddress
import threading
from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests

from app import config
from app.services.threat_feeds import threat_feed_store


@dataclass(frozen=True)
class OsintResult:
    ip: str
    abuse_ok: bool = False
    abuse_score: Optional[float] = None  # 0..100
    vt_ok: bool = False
    vt_score: Optional[float] = None     # 0..100 (malicious ratio)
    feed_score: float = 0.0              # 0..100 from local threat feeds
    feed_sources: str = ""               # comma-separated feed names that matched
    explanation: Optional[list[str]] = None
    error: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


# Simple in-memory TTL cache: ip -> (expires_at_epoch, OsintResult)
_CACHE: Dict[str, Tuple[float, OsintResult]] = {}

# Global seen-set: IPs already checked this session (never re-check via API)
_SEEN_IPS: set = set()
_SEEN_LOCK = threading.Lock()


# ── Per-minute rate limiters ──────────────────────────────────────────────

class _RateLimiter:
    """Sliding-window rate limiter. Non-blocking: returns False if limit hit."""
    def __init__(self, max_per_minute: int):
        self._max = max_per_minute
        self._timestamps: deque = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        now = time.time()
        with self._lock:
            while self._timestamps and self._timestamps[0] < now - 60:
                self._timestamps.popleft()
            if len(self._timestamps) >= self._max:
                return False
            self._timestamps.append(now)
            return True


_abuse_limiter = _RateLimiter(max_per_minute=15)
_vt_limiter = _RateLimiter(max_per_minute=3)


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
        return addr.is_global
    except Exception:
        return False


def _cache_get(ip: str) -> Optional[OsintResult]:
    if not ip:
        return None
    item = _CACHE.get(ip)
    if not item:
        return None
    expires_at, result = item
    if time.time() >= expires_at:
        _CACHE.pop(ip, None)
        return None
    return result


def _cache_set(ip: str, result: OsintResult) -> None:
    ttl = max(int(config.OSINT_CACHE_TTL_SECONDS or 0), 0)
    if ttl <= 0:
        return
    _CACHE[ip] = (time.time() + ttl, result)


def _sleep_rate_limit(resp: requests.Response) -> None:
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            time.sleep(max(0.0, float(retry_after)))
            return
        except Exception:
            pass
    time.sleep(2.0)


def check_abuseipdb(ip: str) -> Dict[str, Any]:
    """AbuseIPDB IP check with local rate limiting."""
    if not config.ABUSEIPDB_API_KEY:
        return {"ok": False, "score": None, "error": "ABUSEIPDB_API_KEY not set", "raw": None}

    if not _abuse_limiter.allow():
        return {"ok": False, "score": None, "error": "rate-limited (local)", "raw": None}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    last_err: Optional[str] = None
    for attempt in range(int(config.OSINT_MAX_RETRIES) + 1):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            if resp.status_code == 429:
                _sleep_rate_limit(resp)
                continue
            if resp.status_code >= 400:
                last_err = f"AbuseIPDB HTTP {resp.status_code}"
                if resp.status_code >= 500 and attempt < int(config.OSINT_MAX_RETRIES):
                    time.sleep(1.0 + attempt)
                    continue
                return {"ok": False, "score": None, "error": last_err, "raw": None}

            data = resp.json()
            score = None
            try:
                score = float((((data or {}).get("data") or {}).get("abuseConfidenceScore")))
            except Exception:
                score = None
            return {"ok": True, "score": score, "error": None, "raw": data}
        except Exception as e:
            last_err = f"AbuseIPDB error: {e}"
            if attempt < int(config.OSINT_MAX_RETRIES):
                time.sleep(1.0 + attempt)
                continue
            return {"ok": False, "score": None, "error": last_err, "raw": None}

    return {"ok": False, "score": None, "error": last_err or "AbuseIPDB failed", "raw": None}


def check_virustotal(ip: str) -> Dict[str, Any]:
    """VirusTotal IP report with local rate limiting."""
    if not config.VIRUSTOTAL_API_KEY:
        return {"ok": False, "score": None, "error": "VIRUSTOTAL_API_KEY not set", "raw": None}

    if not _vt_limiter.allow():
        return {"ok": False, "score": None, "error": "rate-limited (local)", "raw": None}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY, "Accept": "application/json"}

    last_err: Optional[str] = None
    for attempt in range(int(config.OSINT_MAX_RETRIES) + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 429:
                _sleep_rate_limit(resp)
                continue
            if resp.status_code >= 400:
                last_err = f"VirusTotal HTTP {resp.status_code}"
                if resp.status_code >= 500 and attempt < int(config.OSINT_MAX_RETRIES):
                    time.sleep(1.0 + attempt)
                    continue
                return {"ok": False, "score": None, "error": last_err, "raw": None}

            data = resp.json()
            stats = (((data or {}).get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
            malicious = stats.get("malicious", 0) or 0
            harmless = stats.get("harmless", 0) or 0
            suspicious = stats.get("suspicious", 0) or 0
            undetected = stats.get("undetected", 0) or 0
            timeout = stats.get("timeout", 0) or 0
            total = malicious + harmless + suspicious + undetected + timeout
            score = None
            try:
                score = float((malicious / total) * 100.0) if total > 0 else 0.0
            except Exception:
                score = None
            return {"ok": True, "score": score, "error": None, "raw": data}
        except Exception as e:
            last_err = f"VirusTotal error: {e}"
            if attempt < int(config.OSINT_MAX_RETRIES):
                time.sleep(1.0 + attempt)
                continue
            return {"ok": False, "score": None, "error": last_err, "raw": None}

    return {"ok": False, "score": None, "error": last_err or "VirusTotal failed", "raw": None}


def run_osint_checks(ip: str) -> OsintResult:
    """
    Run local threat feeds + AbuseIPDB + VirusTotal for a single IP.
    Local feeds are always checked (free, unlimited).
    API calls are rate-limited and deduplicated across the session.
    """
    ip = (ip or "").strip()
    if not ip:
        return OsintResult(ip=ip, error="missing ip")

    if not config.OSINT_ENABLED:
        return OsintResult(ip=ip, error="OSINT disabled")

    if config.OSINT_SKIP_NON_PUBLIC_IPS and not _is_public_ip(ip):
        return OsintResult(ip=ip, error="non-public ip (skipped)")

    cached = _cache_get(ip)
    if cached is not None:
        return cached

    # Layer 1: local threat feeds (always available, instant)
    feed_result = threat_feed_store.check(ip)

    # Layer 2: API checks (rate-limited, deduplicated)
    with _SEEN_LOCK:
        already_seen = ip in _SEEN_IPS
        _SEEN_IPS.add(ip)

    if already_seen:
        # Already checked via API this session — only return feed data
        explanation = ["OSINT APIs skipped due to session deduplication"]
        if feed_result.score > 0:
            explanation.append("Matched known threat feed")
        result = OsintResult(
            ip=ip,
            feed_score=feed_result.score,
            feed_sources=feed_result.sources,
            explanation=explanation,
            error="already checked (session dedup)",
        )
        _cache_set(ip, result)
        return result

    abuse = check_abuseipdb(ip)
    vt = check_virustotal(ip)

    abuse_ok = bool(abuse.get("ok"))
    vt_ok = bool(vt.get("ok"))
    abuse_score = abuse.get("score")
    vt_score = vt.get("score")

    err_parts = []
    if not abuse.get("ok"):
        err_parts.append(str(abuse.get("error") or "AbuseIPDB failed"))
    if not vt.get("ok"):
        err_parts.append(str(vt.get("error") or "VirusTotal failed"))
    error = "; ".join(err_parts) if err_parts else None

    raw: Dict[str, Any] = {}
    try:
        raw["abuseipdb"] = abuse.get("raw")
    except Exception:
        raw["abuseipdb"] = None
    try:
        raw["virustotal"] = vt.get("raw")
    except Exception:
        raw["virustotal"] = None

    explanation: list[str] = []
    if abuse_ok and (abuse_score or 0) >= 60:
        explanation.append("AbuseIPDB score > threshold")
    if vt_ok and (vt_score or 0) >= 40:
        explanation.append("VirusTotal malicious ratio elevated")
    if feed_result.score > 0:
        explanation.append("Matched known threat feed")
    result = OsintResult(
        ip=ip,
        abuse_ok=abuse_ok,
        abuse_score=abuse_score,
        vt_ok=vt_ok,
        vt_score=vt_score,
        feed_score=feed_result.score,
        feed_sources=feed_result.sources,
        explanation=explanation,
        error=error,
        raw=raw,
    )
    _cache_set(ip, result)
    return result


def osint_verdict_from_final_score(final_score: float, osint_has_data: bool = True) -> str:
    """
    4-tier verdict system:
    - Verified Threat:      ML + OSINT both agree (>70)
    - Suspicious:           strong signal, partial OSINT (40-70)
    - Unconfirmed Threat:   ML flagged it but OSINT has no data (20-40, or any ML-only score)
    - Likely False Positive: weak ML signal AND OSINT says clean (<20)
    """
    if final_score > 70:
        return "Verified Threat"
    if final_score >= 40:
        return "Suspicious"
    if not osint_has_data or final_score >= 20:
        return "Unconfirmed Threat"
    return "Likely False Positive"


def compute_final_score(
    ml_confidence: float,
    abuse_score: Optional[float],
    vt_score: Optional[float],
    rf_confidence: float = 0.0,
    feed_score: float = 0.0,
) -> Tuple[float, bool]:
    """
    Compute a combined threat score (0..100).

    Args:
        ml_confidence: anomaly_score * 100 (0..100)
        abuse_score:   AbuseIPDB confidence (0..100), None if unavailable
        vt_score:      VirusTotal malicious ratio (0..100), None if unavailable
        rf_confidence: RF classification confidence (0..1), 0 if no supervised model
        feed_score:    local threat feed score (0..100), 0 if IP not in any feed

    Returns:
        (final_score, osint_has_data)
    """
    a = float(abuse_score) if abuse_score is not None else 0.0
    v = float(vt_score) if vt_score is not None else 0.0
    m = float(ml_confidence)
    rf = float(rf_confidence) * 100.0  # normalize to 0..100
    f = float(feed_score)

    api_has_data = (abuse_score is not None and abuse_score > 0) or \
                   (vt_score is not None and vt_score > 0)
    feeds_have_data = f > 0
    osint_has_data = api_has_data or feeds_have_data

    if api_has_data:
        # Full formula: ML + RF + feeds + API OSINT
        final = (m * 0.30) + (rf * 0.20) + (f * 0.20) + (a * 0.15) + (v * 0.15)
    elif feeds_have_data:
        # API quota exhausted but feeds found a match
        final = (m * 0.35) + (rf * 0.25) + (f * 0.40)
    else:
        # No external data at all — pure ML
        final = (m * 0.5) + (rf * 0.5)

    return max(0.0, min(100.0, final)), osint_has_data
