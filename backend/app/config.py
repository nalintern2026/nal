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


def _env_str(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    if v is None:
        return default
    return str(v).strip()


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

# ── API Security ───────────────────────────────────────────────────────────
API_KEY_HEADER: str = "x-api-key"
API_KEY: str | None = _env_str("NETGUARD_API_KEY", default="") or None

# ── Upload Constraints ─────────────────────────────────────────────────────
# 200MB default hard limit for upload endpoint.
UPLOAD_MAX_FILE_SIZE_BYTES: int = _env_int("UPLOAD_MAX_FILE_SIZE_BYTES", default=200 * 1024 * 1024)

# ── CORS ───────────────────────────────────────────────────────────────────
# Comma-separated origins; defaults to local frontend hosts.
_DEFAULT_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173,http://0.0.0.0:5173"
CORS_ALLOWED_ORIGINS: list[str] = [
    o.strip() for o in _env_str("CORS_ALLOWED_ORIGINS", _DEFAULT_ORIGINS).split(",") if o.strip()
]

# ── Database / Retention ───────────────────────────────────────────────────
DATABASE_URL: str = _env_str("DATABASE_URL", "sqlite:///")
DATA_RETENTION_DAYS: int = _env_int("DATA_RETENTION_DAYS", 30)
ALERT_FINAL_SCORE_THRESHOLD: float = float(_env_str("ALERT_FINAL_SCORE_THRESHOLD", "70"))
ALERT_CORRELATION_WINDOW_MINUTES: int = _env_int("ALERT_CORRELATION_WINDOW_MINUTES", 10)
REDIS_URL: str = _env_str("REDIS_URL", "redis://localhost:6379")

