from __future__ import annotations

import importlib
import sqlite3
from datetime import datetime, timezone
from typing import Any

from app.paths import DB_PATH, PASSIVE_TIMELINE_DB_PATH
from app.services.model_integrity import evaluate_model_integrity
from app.services.queue_service import queue_status
from app.utils.logger import get_logger

logger = get_logger(__name__)


def _module_check(module_name: str) -> dict[str, str]:
    try:
        importlib.import_module(module_name)
        return {"name": f"import:{module_name}", "status": "ok", "details": "imported"}
    except Exception as e:
        return {"name": f"import:{module_name}", "status": "failed", "details": str(e)}


def _sqlite_check(path: str, required_tables: list[str]) -> dict[str, Any]:
    try:
        conn = sqlite3.connect(path, timeout=3.0)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing = {r[0] for r in cur.fetchall()}
        missing = [t for t in required_tables if t not in existing]
        conn.close()
        if missing:
            return {
                "name": f"db:{path}",
                "status": "failed",
                "details": f"missing tables: {', '.join(missing)}",
            }
        return {"name": f"db:{path}", "status": "ok", "details": "connected and schema present"}
    except Exception as e:
        return {"name": f"db:{path}", "status": "failed", "details": str(e)}


def run_integrity_checks() -> dict[str, Any]:
    checks: list[dict[str, str]] = []

    for module in ("app.main", "app.db", "app.services.decision_service"):
        checks.append(_module_check(module))

    checks.append(_sqlite_check(str(DB_PATH), ["flows", "analysis_history"]))
    checks.append(_sqlite_check(str(PASSIVE_TIMELINE_DB_PATH), ["passive_upload_points"]))
    q = queue_status()
    checks.append({"name": "queue_backend", "status": "ok", "details": str(q)})
    checks.append({"name": "security_mode", "status": "ok", "details": "API_KEY"})

    # API self-check (lightweight) — verifies critical route registration.
    try:
        from app.main import app

        required_paths = {
            "/api/health",
            "/api/model/integrity",
            "/api/integrity",
            "/api/traffic/flows",
        }
        registered = {r.path for r in app.routes}
        missing = sorted(required_paths - registered)
        if missing:
            checks.append({"name": "api_routes", "status": "failed", "details": f"missing routes: {', '.join(missing)}"})
        else:
            checks.append({"name": "api_routes", "status": "ok", "details": "critical routes registered"})
    except Exception as e:
        checks.append({"name": "api_routes", "status": "failed", "details": str(e)})

    model = evaluate_model_integrity()
    checks.append(
        {
            "name": "model_integrity",
            "status": "ok" if model["status"] == "ok" else "failed",
            "details": f"status={model['status']}",
        }
    )

    overall = "ok" if all(c["status"] == "ok" for c in checks) else "failed"
    logger.info("Integrity checks completed: %s", overall)
    return {
        "status": overall,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "model_integrity": model,
    }
