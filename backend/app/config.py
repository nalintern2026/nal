"""
Backend runtime configuration.

Secrets (API keys) are read from environment variables so they are not committed to git.
The .env file is loaded here (earliest possible point) so all config values see the keys.
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv  # type: ignore

    _env_path = Path(__file__).resolve().parent.parent.parent / ".env"  # nal/.env
    load_dotenv(dotenv_path=_env_path, override=False)
except Exception:
    pass


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None or not str(v).strip():
        return default
    try:
        return int(str(v).strip())
    except Exception:
        return default


# ── OSINT / Threat Intel ──────────────────────────────────────────────────

# Toggle OSINT lookups globally.
OSINT_ENABLED: bool = _env_bool("OSINT_ENABLED", default=True)

# API keys (set in environment or .env loaded by your process manager).
ABUSEIPDB_API_KEY: str | None = os.environ.get("ABUSEIPDB_API_KEY") or None
VIRUSTOTAL_API_KEY: str | None = os.environ.get("VIRUSTOTAL_API_KEY") or None

# Cache TTL to reduce external API calls (seconds).
OSINT_CACHE_TTL_SECONDS: int = _env_int("OSINT_CACHE_TTL_SECONDS", default=3600)

# Max retries for transient failures / rate limits.
OSINT_MAX_RETRIES: int = _env_int("OSINT_MAX_RETRIES", default=2)

# When true, skip OSINT lookups for private/reserved/loopback IPs.
OSINT_SKIP_NON_PUBLIC_IPS: bool = _env_bool("OSINT_SKIP_NON_PUBLIC_IPS", default=True)

