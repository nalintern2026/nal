from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def success(data: Any = None, status: str = "SUCCESS") -> dict[str, Any]:
    return {
        "status": status,
        "data": data if data is not None else {},
        "error": None,
        "timestamp": _ts(),
    }


def failed(code: str, message: str, data: Any = None, status: str = "FAILED") -> dict[str, Any]:
    return {
        "status": status,
        "data": data if data is not None else {},
        "error": {"code": code, "message": message},
        "timestamp": _ts(),
    }


def degraded(data: Any = None, code: str = "DEGRADED", message: str = "Partial functionality") -> dict[str, Any]:
    return {
        "status": "DEGRADED",
        "data": data if data is not None else {},
        "error": {"code": code, "message": message},
        "timestamp": _ts(),
    }
