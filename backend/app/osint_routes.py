from __future__ import annotations

from typing import Optional

from fastapi import APIRouter

from app import db
from app.utils.response import success

router = APIRouter(prefix="/api/osint", tags=["osint"])


@router.get("/flows")
async def get_osint_flows(
    page: int = 1,
    per_page: int = 20,
    src_ip: Optional[str] = None,
    monitor_type: Optional[str] = None,
):
    """
    Return only flows that have OSINT enrichment populated.
    monitor_type: 'passive', 'active', or None for combined.
    """
    per_page = max(1, min(per_page, 200))
    flows, total = db.get_osint_flows(
        page=page,
        per_page=per_page,
        src_ip=src_ip,
        monitor_type=monitor_type,
    )
    return success({
        "flows": flows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
    })

