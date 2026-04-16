from __future__ import annotations

import queue
import threading
from typing import Any

from app import db
from app.utils.logger import get_logger

logger = get_logger(__name__)

_flow_queue: "queue.Queue[tuple[list[dict[str, Any]], str]]" = queue.Queue(maxsize=200)
_stop = threading.Event()


def enqueue_flows(flows: list[dict[str, Any]], monitor_type: str) -> bool:
    try:
        _flow_queue.put((flows, monitor_type), timeout=1.0)
        return True
    except queue.Full:
        logger.error("Flow queue full; dropping batch")
        return False


def _worker() -> None:
    while not _stop.is_set():
        try:
            flows, monitor_type = _flow_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        try:
            db.insert_flows(flows, monitor_type=monitor_type)
        except Exception as e:
            logger.error("Flow queue write failed: %s", e, exc_info=True)
        finally:
            _flow_queue.task_done()


_thread = threading.Thread(target=_worker, daemon=True)
_thread.start()


def wait_for_drain(timeout_s: float = 5.0) -> None:
    _flow_queue.join()


def shutdown() -> None:
    _stop.set()
