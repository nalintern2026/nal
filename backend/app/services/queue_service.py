from __future__ import annotations

import json
import threading
import time
from typing import Any

from app import config, db
from app.services.flow_queue import enqueue_flows as fallback_enqueue
from app.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import redis  # type: ignore
except Exception:
    redis = None

_redis_client = None
_QUEUE_KEY = "netguard:flow_batches"
_running = False


def _get_redis():
    global _redis_client
    if redis is None:
        return None
    if _redis_client is not None:
        return _redis_client
    try:
        _redis_client = redis.Redis.from_url(config.REDIS_URL, decode_responses=True)
        _redis_client.ping()
        return _redis_client
    except Exception:
        _redis_client = None
        return None


def enqueue_flow_batch(flows: list[dict[str, Any]], monitor_type: str) -> bool:
    client = _get_redis()
    if client is None:
        return fallback_enqueue(flows, monitor_type)
    try:
        payload = json.dumps({"flows": flows, "monitor_type": monitor_type, "retries": 0})
        client.rpush(_QUEUE_KEY, payload)
        return True
    except Exception:
        return fallback_enqueue(flows, monitor_type)


def _worker_loop() -> None:
    global _running
    _running = True
    while _running:
        client = _get_redis()
        if client is None:
            time.sleep(1.0)
            continue
        try:
            item = client.blpop(_QUEUE_KEY, timeout=2)
            if not item:
                continue
            _, raw = item
            payload = json.loads(raw)
            flows = payload.get("flows") or []
            monitor_type = payload.get("monitor_type") or "passive"
            retries = int(payload.get("retries") or 0)
            try:
                db.insert_flows(flows, monitor_type=monitor_type)
            except Exception as e:
                if retries < 3:
                    payload["retries"] = retries + 1
                    client.rpush(_QUEUE_KEY, json.dumps(payload))
                else:
                    logger.error("Dropping redis queue batch after retries: %s", e)
        except Exception:
            time.sleep(1.0)


threading.Thread(target=_worker_loop, daemon=True).start()


def queue_status() -> dict[str, Any]:
    client = _get_redis()
    if client is None:
        return {"backend": "inprocess_fallback", "redis": "unavailable"}
    try:
        depth = int(client.llen(_QUEUE_KEY))
    except Exception:
        depth = -1
    return {"backend": "redis", "redis": "connected", "depth": depth}
