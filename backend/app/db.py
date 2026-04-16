"""
Database module for storing network flows.
Uses SQLite for persistent storage with pagination support.
"""
import sqlite3
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
import threading
import time

from app.paths import DB_PATH, PASSIVE_TIMELINE_DB_PATH, DATA_ROOT
from app import config

# Thread-safe database operations
db_lock = threading.Lock()

# Dedicated store for the dashboard **passive** Traffic Timeline only (decoupled from flows.db queries).
passive_timeline_lock = threading.Lock()

# Protocol filter: DB may store number ("6") or name ("TCP") from different sources. Match both.
PROTOCOL_FILTER_VALUES = {
    "TCP": ("6", "TCP"),
    "UDP": ("17", "UDP"),
    "ICMP": ("1", "ICMP"),
    "GRE": ("47", "GRE"),
    "ESP": ("50", "ESP"),
    "AH": ("51", "AH"),
    "OSPF": ("89", "OSPF"),
    "SCTP": ("132", "SCTP"),
}


def _ensure_data_root() -> None:
    DATA_ROOT.mkdir(parents=True, exist_ok=True)


def _apply_connection_pragmas(conn: sqlite3.Connection) -> None:
    if not str(config.DATABASE_URL).startswith("sqlite"):
        return
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")


def _connect_with_retry(path: str, retries: int = 3, delay_s: float = 0.2) -> sqlite3.Connection:
    last_error: Exception | None = None
    for _ in range(retries):
        try:
            conn = sqlite3.connect(path, timeout=5.0, check_same_thread=False)
            _apply_connection_pragmas(conn)
            return conn
        except sqlite3.OperationalError as e:
            last_error = e
            time.sleep(delay_s)
    raise RuntimeError(f"Unable to connect to SQLite database at {path}: {last_error}")


def get_connection() -> sqlite3.Connection:
    return _connect_with_retry(str(DB_PATH))


def execute(query: str, params: tuple = ()) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(query, params)
    conn.commit()
    conn.close()


def fetchall(query: str, params: tuple = ()) -> list[dict[str, Any]]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(query, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def fetchone(query: str, params: tuple = ()) -> Optional[dict[str, Any]]:
    rows = fetchall(query, params)
    return rows[0] if rows else None


def init_db():
    """Initialize database schema."""
    _ensure_data_root()
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id TEXT PRIMARY KEY,
                analysis_id TEXT,
                upload_filename TEXT,
                timestamp TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                duration REAL,
                total_fwd_packets INTEGER,
                total_bwd_packets INTEGER,
                total_length_fwd INTEGER,
                total_length_bwd INTEGER,
                flow_bytes_per_sec REAL,
                flow_packets_per_sec REAL,
                classification TEXT,
                confidence REAL,
                anomaly_score REAL,
                risk_score REAL,
                risk_level TEXT,
                is_anomaly BOOLEAN,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Backward-compatible schema upgrades for existing DBs.
        cursor.execute("PRAGMA table_info(flows)")
        existing_columns = {row[1] for row in cursor.fetchall()}
        if "analysis_id" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN analysis_id TEXT")
        if "upload_filename" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN upload_filename TEXT")
        if "threat_type" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN threat_type TEXT")
        if "cve_refs" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN cve_refs TEXT")
        if "classification_reason" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN classification_reason TEXT")
        if "monitor_type" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN monitor_type TEXT DEFAULT 'passive'")
        if "osint_ip" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN osint_ip TEXT")
        if "abuse_score" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN abuse_score REAL")
        if "vt_score" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN vt_score REAL")
        if "final_score" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN final_score REAL")
        if "final_verdict" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN final_verdict TEXT")
        if "osint_error" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN osint_error TEXT")
        if "abuse_ok" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN abuse_ok BOOLEAN")
        if "vt_ok" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN vt_ok BOOLEAN")
        if "feed_score" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN feed_score REAL")
        if "feed_sources" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN feed_sources TEXT")
        if "explanation" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN explanation TEXT")
        if "model_version" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN model_version TEXT")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS upload_jobs (
                job_id TEXT PRIMARY KEY,
                status TEXT,
                created_at TEXT,
                completed_at TEXT,
                error TEXT,
                filename TEXT,
                result_summary TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_upload_jobs_created_at ON upload_jobs(created_at DESC)")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id TEXT,
                risk_level TEXT,
                classification TEXT,
                created_at TEXT,
                status TEXT,
                reason TEXT,
                priority TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        cursor.execute("PRAGMA table_info(alerts)")
        alert_cols = {row[1] for row in cursor.fetchall()}
        if "correlation_id" not in alert_cols:
            cursor.execute("ALTER TABLE alerts ADD COLUMN correlation_id TEXT")
        if "source_ip" not in alert_cols:
            cursor.execute("ALTER TABLE alerts ADD COLUMN source_ip TEXT")
        if "destination_ip" not in alert_cols:
            cursor.execute("ALTER TABLE alerts ADD COLUMN destination_ip TEXT")
        if "last_seen" not in alert_cols:
            cursor.execute("ALTER TABLE alerts ADD COLUMN last_seen TEXT")
        if "occurrence_count" not in alert_cols:
            cursor.execute("ALTER TABLE alerts ADD COLUMN occurrence_count INTEGER DEFAULT 1")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS model_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT UNIQUE,
                created_at TEXT,
                metrics TEXT,
                is_active BOOLEAN
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON flows(timestamp DESC);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_classification ON flows(classification);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_risk_level ON flows(risk_level);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_analysis_id ON flows(analysis_id);
        """)

        # Analysis history: metadata for each upload/analysis (persists across refresh)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                analysis_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                monitor_type TEXT NOT NULL DEFAULT 'Static Monitoring',
                uploaded_at TEXT NOT NULL,
                file_size INTEGER,
                total_flows INTEGER DEFAULT 0,
                anomaly_count INTEGER DEFAULT 0,
                avg_risk_score REAL DEFAULT 0,
                attack_distribution TEXT,
                risk_distribution TEXT,
                report_details TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_analysis_history_uploaded_at ON analysis_history(uploaded_at DESC);
        """)

        # analysis_history: ensure monitor_type exists for old DBs created before this column
        cursor.execute("PRAGMA table_info(analysis_history)")
        ah_columns = {row[1] for row in cursor.fetchall()}
        if "monitor_type" not in ah_columns:
            cursor.execute("ALTER TABLE analysis_history ADD COLUMN monitor_type TEXT DEFAULT 'passive'")
        
        conn.commit()
        conn.close()

    init_passive_timeline_db()


def init_passive_timeline_db() -> None:
    """Create passive_timeline.db and optional backfill from main DB when empty."""
    _ensure_data_root()
    with passive_timeline_lock:
        conn = _connect_with_retry(str(PASSIVE_TIMELINE_DB_PATH))
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passive_upload_points (
                analysis_id TEXT PRIMARY KEY,
                uploaded_at TEXT NOT NULL,
                total_flows INTEGER NOT NULL DEFAULT 0,
                anomaly_count INTEGER NOT NULL DEFAULT 0,
                filename TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_passive_upload_points_time
            ON passive_upload_points(uploaded_at ASC)
        """)
        cursor.execute("SELECT COUNT(*) FROM passive_upload_points")
        n = cursor.fetchone()[0]
        conn.commit()
        conn.close()

    if n == 0:
        _backfill_passive_timeline_store()


def _backfill_passive_timeline_store() -> None:
    """Seed passive_timeline.db from analysis_history + flows fallback (same universe as History)."""
    try:
        hist = get_analysis_history(limit=500, monitor_type="passive")
    except Exception:
        return
    for h in hist:
        aid = h.get("analysis_id")
        if not aid:
            continue
        record_passive_timeline_point(
            str(aid),
            str(h.get("uploaded_at") or ""),
            int(h.get("total_flows") or 0),
            int(h.get("anomaly_count") or 0),
            str(h.get("filename") or ""),
        )


def record_passive_timeline_point(
    analysis_id: str,
    uploaded_at: str,
    total_flows: int,
    anomaly_count: int,
    filename: str = "",
) -> None:
    """Append/update one passive upload point for the dashboard bar chart (separate DB)."""
    if not analysis_id or not str(uploaded_at).strip():
        return
    with passive_timeline_lock:
        conn = _connect_with_retry(str(PASSIVE_TIMELINE_DB_PATH))
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO passive_upload_points
            (analysis_id, uploaded_at, total_flows, anomaly_count, filename)
            VALUES (?, ?, ?, ?, ?)
            """,
            (analysis_id, uploaded_at, total_flows, anomaly_count, filename or None),
        )
        conn.commit()
        conn.close()


def get_passive_timeline_points(limit: int = 40) -> List[Dict[str, Any]]:
    """Points for passive Traffic Timeline: oldest first, cap `limit` most recent uploads."""
    with passive_timeline_lock:
        conn = _connect_with_retry(str(PASSIVE_TIMELINE_DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                SELECT uploaded_at AS hour, total_flows AS total, anomaly_count AS anomalies
                FROM passive_upload_points
                ORDER BY uploaded_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = [dict(row) for row in cursor.fetchall()]
        except sqlite3.OperationalError:
            rows = []
        conn.close()
    return list(reversed(rows))


def insert_analysis(
    analysis_id: str,
    filename: str,
    monitor_type: str,
    file_size: Optional[int],
    total_flows: int,
    anomaly_count: int,
    avg_risk_score: float,
    attack_distribution: Dict[str, int],
    risk_distribution: Dict[str, int],
    report_details: Optional[Dict[str, Any]] = None,
) -> None:
    """Insert or replace analysis metadata into history."""
    uploaded_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO analysis_history (
                analysis_id, filename, monitor_type, uploaded_at, file_size,
                total_flows, anomaly_count, avg_risk_score,
                attack_distribution, risk_distribution, report_details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis_id,
            filename,
            monitor_type or "Static Monitoring",
            uploaded_at,
            file_size,
            total_flows,
            anomaly_count,
            avg_risk_score,
            json.dumps(attack_distribution or {}),
            json.dumps(risk_distribution or {}),
            json.dumps(report_details or {}),
        ))
        conn.commit()
        conn.close()

    mt = (monitor_type or "passive").strip().lower()
    if mt != "active":
        record_passive_timeline_point(
            analysis_id, uploaded_at, total_flows, anomaly_count, filename
        )


def get_analysis_history(limit: int = 100, monitor_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all analyses ordered by upload time (newest first). Includes fallback from flows for pre-feature uploads.
    monitor_type: 'passive', 'active', or None for combined. Passive = Static Monitoring/upload; Active = live capture sessions."""
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if monitor_type and str(monitor_type).strip().lower() == "passive":
            cursor.execute("""
                SELECT analysis_id, filename, monitor_type, uploaded_at, file_size,
                       total_flows, anomaly_count, avg_risk_score,
                       attack_distribution, risk_distribution, report_details
                FROM analysis_history
                WHERE COALESCE(monitor_type, 'passive') IN ('passive', 'Static Monitoring', '')
                ORDER BY uploaded_at DESC
                LIMIT ?
            """, (limit,))
        elif monitor_type and str(monitor_type).strip().lower() == "active":
            cursor.execute("""
                SELECT analysis_id, filename, monitor_type, uploaded_at, file_size,
                       total_flows, anomaly_count, avg_risk_score,
                       attack_distribution, risk_distribution, report_details
                FROM analysis_history
                WHERE LOWER(COALESCE(monitor_type, '')) = 'active'
                ORDER BY uploaded_at DESC
                LIMIT ?
            """, (limit,))
        else:
            cursor.execute("""
                SELECT analysis_id, filename, monitor_type, uploaded_at, file_size,
                       total_flows, anomaly_count, avg_risk_score,
                       attack_distribution, risk_distribution, report_details
                FROM analysis_history
                ORDER BY uploaded_at DESC
                LIMIT ?
            """, (limit,))
        rows = list(cursor.fetchall())

        # Fallback: analyses from flows that have no history row (pre-feature uploads). Only for combined/passive.
        fallback_rows = []
        if not monitor_type or str(monitor_type).strip().lower() == "passive":
            cursor.execute("""
                SELECT analysis_id, upload_filename as filename,
                       MIN(timestamp) as uploaded_at, COUNT(*) as total_flows,
                       SUM(CASE WHEN is_anomaly THEN 1 ELSE 0 END) as anomaly_count,
                       AVG(risk_score) as avg_risk_score
                FROM flows
                WHERE analysis_id IS NOT NULL AND analysis_id != ''
                  AND analysis_id NOT IN (SELECT analysis_id FROM analysis_history)
                  AND COALESCE(monitor_type, 'passive') = 'passive'
                GROUP BY analysis_id
            """)
            fallback_rows = cursor.fetchall()

        # Fallback for active flows: they may have analysis_id (session-based) or NULL (legacy).
        # Group legacy NULL-id active flows by date to create synthetic session entries.
        active_fallback_rows = []
        if not monitor_type or str(monitor_type).strip().lower() == "active":
            cursor.execute("""
                SELECT COALESCE(analysis_id, 'active-' || DATE(timestamp)) as analysis_id,
                       'realtime' as filename,
                       MIN(timestamp) as uploaded_at, COUNT(*) as total_flows,
                       SUM(CASE WHEN is_anomaly THEN 1 ELSE 0 END) as anomaly_count,
                       AVG(risk_score) as avg_risk_score
                FROM flows
                WHERE LOWER(COALESCE(monitor_type, '')) = 'active'
                  AND (analysis_id IS NULL OR analysis_id = ''
                       OR analysis_id NOT IN (SELECT analysis_id FROM analysis_history))
                GROUP BY COALESCE(analysis_id, 'active-' || DATE(timestamp))
            """)
            active_fallback_rows = cursor.fetchall()
        conn.close()

    seen_ids = set()
    result = []
    for row in rows:
        r = dict(row)
        seen_ids.add(r["analysis_id"])
        try:
            r["attack_distribution"] = json.loads(r["attack_distribution"] or "{}")
        except (TypeError, json.JSONDecodeError):
            r["attack_distribution"] = {}
        try:
            r["risk_distribution"] = json.loads(r["risk_distribution"] or "{}")
        except (TypeError, json.JSONDecodeError):
            r["risk_distribution"] = {}
        try:
            r["report_details"] = json.loads(r["report_details"] or "{}")
        except (TypeError, json.JSONDecodeError):
            r["report_details"] = {}
        result.append(r)

    for row in fallback_rows:
        r = dict(row)
        if r["analysis_id"] in seen_ids:
            continue
        seen_ids.add(r["analysis_id"])
        r["filename"] = r.get("filename") or "Unknown"
        r["monitor_type"] = "Static Monitoring"
        r["file_size"] = None
        r["attack_distribution"] = {}
        r["risk_distribution"] = {}
        r["report_details"] = {}
        result.append(r)

    for row in active_fallback_rows:
        r = dict(row)
        if r["analysis_id"] in seen_ids:
            continue
        seen_ids.add(r["analysis_id"])
        r["filename"] = "Active Monitoring Session"
        r["monitor_type"] = "active"
        r["file_size"] = None
        r["attack_distribution"] = {}
        r["risk_distribution"] = {}
        r["report_details"] = {}
        result.append(r)

    result.sort(key=lambda x: x.get("uploaded_at") or "", reverse=True)
    return result[:limit]


def _get_active_flows_by_date(date_str: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Fetch active monitoring flows for a given date (YYYY-MM-DD), used for synthetic session IDs."""
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM flows
            WHERE LOWER(COALESCE(monitor_type, '')) = 'active'
              AND (analysis_id IS NULL OR analysis_id = '')
              AND DATE(timestamp) = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (date_str, limit))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
    return rows


def get_analysis_report(analysis_id: str) -> Optional[Dict[str, Any]]:
    """Get full report for one analysis (metadata + flows)."""
    aid = analysis_id.strip()
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT analysis_id, filename, monitor_type, uploaded_at, file_size,
                   total_flows, anomaly_count, avg_risk_score,
                   attack_distribution, risk_distribution, report_details
            FROM analysis_history
            WHERE analysis_id = ?
        """, (aid,))
        row = cursor.fetchone()

        if not row:
            # Check if this is a synthetic active session ID (e.g. "active-2026-04-13")
            is_active_synthetic = aid.startswith("active-") and len(aid) == len("active-YYYY-MM-DD")
            if is_active_synthetic:
                date_part = aid[len("active-"):]
                cursor.execute(
                    """SELECT COUNT(*) as cnt, AVG(risk_score) as avg_risk FROM flows
                       WHERE LOWER(COALESCE(monitor_type, '')) = 'active'
                         AND (analysis_id IS NULL OR analysis_id = '')
                         AND DATE(timestamp) = ?""",
                    (date_part,),
                )
            else:
                cursor.execute(
                    "SELECT COUNT(*) as cnt, AVG(risk_score) as avg_risk FROM flows WHERE analysis_id = ?",
                    (aid,),
                )
            flow_row = cursor.fetchone()
            if flow_row and flow_row["cnt"] and flow_row["cnt"] > 0:
                if is_active_synthetic:
                    cursor.execute(
                        """SELECT MIN(timestamp) as ts FROM flows
                           WHERE LOWER(COALESCE(monitor_type, '')) = 'active'
                             AND (analysis_id IS NULL OR analysis_id = '')
                             AND DATE(timestamp) = ?""",
                        (date_part,),
                    )
                    fn_row = cursor.fetchone()
                    filename = "Active Monitoring Session"
                    mt_label = "active"
                else:
                    cursor.execute(
                        "SELECT upload_filename, MIN(timestamp) as ts FROM flows WHERE analysis_id = ?",
                        (aid,),
                    )
                    fn_row = cursor.fetchone()
                    filename = (fn_row and fn_row["upload_filename"]) or "Unknown"
                    mt_label = "Static Monitoring"
                meta = {
                    "analysis_id": aid,
                    "filename": filename,
                    "monitor_type": mt_label,
                    "uploaded_at": (fn_row and fn_row["ts"]) or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + 'Z',
                    "file_size": None,
                    "total_flows": flow_row["cnt"],
                    "anomaly_count": 0,
                    "avg_risk_score": float(flow_row["avg_risk"] or 0),
                    "attack_distribution": "{}",
                    "risk_distribution": "{}",
                    "report_details": "{}",
                }
                if is_active_synthetic:
                    flow_filter = """LOWER(COALESCE(monitor_type, '')) = 'active'
                                     AND (analysis_id IS NULL OR analysis_id = '')
                                     AND DATE(timestamp) = ?"""
                    filter_param = (date_part,)
                else:
                    flow_filter = "analysis_id = ?"
                    filter_param = (aid,)

                cursor.execute(
                    f"SELECT classification, COUNT(*) as c FROM flows WHERE {flow_filter} GROUP BY classification",
                    filter_param,
                )
                attack_dist = {r["classification"] or "Unknown": r["c"] for r in cursor.fetchall()}
                cursor.execute(
                    f"SELECT risk_level, COUNT(*) as c FROM flows WHERE {flow_filter} GROUP BY risk_level",
                    filter_param,
                )
                risk_dist = {r["risk_level"] or "Low": r["c"] for r in cursor.fetchall()}
                meta["attack_distribution"] = json.dumps(attack_dist)
                meta["risk_distribution"] = json.dumps(risk_dist)
                cursor.execute(
                    f"SELECT SUM(CASE WHEN is_anomaly THEN 1 ELSE 0 END) as anom FROM flows WHERE {flow_filter}",
                    filter_param,
                )
                meta["anomaly_count"] = cursor.fetchone()["anom"] or 0
            else:
                conn.close()
                return None
        else:
            meta = dict(row)
        conn.close()
    try:
        meta["attack_distribution"] = json.loads(meta["attack_distribution"] or "{}")
    except (TypeError, json.JSONDecodeError):
        meta["attack_distribution"] = {}
    try:
        meta["risk_distribution"] = json.loads(meta["risk_distribution"] or "{}")
    except (TypeError, json.JSONDecodeError):
        meta["risk_distribution"] = {}
    try:
        meta["report_details"] = json.loads(meta["report_details"] or "{}")
    except (TypeError, json.JSONDecodeError):
        meta["report_details"] = {}

    is_active_synthetic = aid.startswith("active-") and len(aid) == len("active-YYYY-MM-DD")
    if is_active_synthetic:
        date_part = aid[len("active-"):]
        flows = _get_active_flows_by_date(date_part, limit=500)
        total = len(flows)
    else:
        flows, total = get_flows(analysis_id=aid, page=1, per_page=500)
    return {
        "id": meta["analysis_id"],
        "filename": meta["filename"],
        "monitor_type": meta["monitor_type"],
        "uploaded_at": meta["uploaded_at"],
        "file_size": meta["file_size"],
        "total_flows": meta["total_flows"],
        "anomaly_count": meta["anomaly_count"],
        "avg_risk_score": meta["avg_risk_score"],
        "attack_distribution": meta["attack_distribution"],
        "risk_distribution": meta["risk_distribution"],
        "report_details": meta["report_details"],
        "flows": flows,
        "sample_flows": flows[:50],
    }


def insert_flows(flows: List[Dict[str, Any]], monitor_type: str = "passive") -> int:
    """Insert flows into database. Returns count of inserted flows.
    monitor_type: 'passive' for file uploads, 'active' for realtime monitoring."""
    if not flows:
        return 0
    mt = monitor_type or "passive"

    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        cursor = conn.cursor()

        inserted = 0
        for flow in flows:
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO flows (
                        id, analysis_id, upload_filename, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                        duration, total_fwd_packets, total_bwd_packets, total_length_fwd,
                        total_length_bwd, flow_bytes_per_sec, flow_packets_per_sec,
                        classification, threat_type, cve_refs, classification_reason,
                        confidence, anomaly_score, risk_score, risk_level, is_anomaly, monitor_type,
                        osint_ip, abuse_score, vt_score, final_score, final_verdict,
                        osint_error, abuse_ok, vt_ok, feed_score, feed_sources, explanation, model_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    flow.get('id'),
                    flow.get('analysis_id'),
                    flow.get('upload_filename'),
                    flow.get('timestamp'),
                    flow.get('src_ip'),
                    flow.get('dst_ip'),
                    flow.get('src_port'),
                    flow.get('dst_port'),
                    flow.get('protocol'),
                    flow.get('duration'),
                    flow.get('total_fwd_packets'),
                    flow.get('total_bwd_packets'),
                    flow.get('total_length_fwd'),
                    flow.get('total_length_bwd'),
                    flow.get('flow_bytes_per_sec'),
                    flow.get('flow_packets_per_sec'),
                    flow.get('classification'),
                    flow.get('threat_type') or '',
                    flow.get('cve_refs') or '',
                    flow.get('classification_reason') or '',
                    flow.get('confidence'),
                    flow.get('anomaly_score'),
                    flow.get('risk_score'),
                    flow.get('risk_level'),
                    flow.get('is_anomaly', False),
                    flow.get('monitor_type', mt),
                    flow.get('osint_ip'),
                    flow.get('abuse_score'),
                    flow.get('vt_score'),
                    flow.get('final_score'),
                    flow.get('final_verdict'),
                    flow.get('osint_error'),
                    flow.get('abuse_ok'),
                    flow.get('vt_ok'),
                    flow.get('feed_score'),
                    flow.get('feed_sources'),
                    json.dumps(flow.get("explanation", [])),
                    flow.get("model_version"),
                ))
                inserted += 1
            except Exception as e:
                print(f"Error inserting flow {flow.get('id')}: {e}")
                continue
        
        conn.commit()
        conn.close()
        return inserted


def get_flows(
    page: int = 1,
    per_page: int = 20,
    classification: Optional[str] = None,
    risk_level: Optional[str] = None,
    threat_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    analysis_id: Optional[str] = None,
    monitor_type: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Get paginated flows with optional filters. Returns (flows, total_count).
    monitor_type: 'passive', 'active', or None for combined."""
    
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Build WHERE clause
        where_clauses = []
        params = []
        
        if monitor_type and str(monitor_type).strip().lower() in ("passive", "active"):
            where_clauses.append("COALESCE(monitor_type, 'passive') = ?")
            params.append(str(monitor_type).strip().lower())
        
        if classification:
            where_clauses.append("LOWER(COALESCE(classification, '')) = LOWER(?)")
            params.append(classification.strip())
        if risk_level:
            where_clauses.append("LOWER(COALESCE(risk_level, '')) = LOWER(?)")
            params.append(risk_level.strip())
        if threat_type:
            where_clauses.append("LOWER(COALESCE(threat_type, '')) = LOWER(?)")
            params.append(threat_type.strip())
        if src_ip:
            where_clauses.append("LOWER(COALESCE(src_ip, '')) LIKE LOWER(?)")
            params.append(f"%{src_ip.strip()}%")
        if protocol:
            protocol_clean = protocol.strip()
            if protocol_clean.upper() in PROTOCOL_FILTER_VALUES:
                vals = PROTOCOL_FILTER_VALUES[protocol_clean.upper()]
                placeholders = ", ".join("?" for _ in vals)
                where_clauses.append(f"(COALESCE(protocol, '') IN ({placeholders}))")
                params.extend(vals)
            else:
                where_clauses.append("LOWER(COALESCE(protocol, '')) = LOWER(?)")
                params.append(protocol_clean)
        if analysis_id:
            where_clauses.append("LOWER(COALESCE(analysis_id, '')) = LOWER(?)")
            params.append(analysis_id.strip())
        
        where_sql = " AND ".join(where_clauses)
        where_sql = f"WHERE {where_sql}" if where_sql else ""
        
        # Get total count
        count_query = f"SELECT COUNT(*) as cnt FROM flows {where_sql}"
        cursor.execute(count_query, params)
        total = cursor.fetchone()['cnt']
        
        # Get paginated results
        offset = (page - 1) * per_page
        query = f"""
            SELECT * FROM flows {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        cursor.execute(query, params + [per_page, offset])
        rows = cursor.fetchall()
        
        flows = [dict(row) for row in rows]
        conn.close()
        
        return flows, total


def get_osint_flows(
    page: int = 1,
    per_page: int = 20,
    src_ip: Optional[str] = None,
    monitor_type: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Get paginated flows that have OSINT enrichment populated."""
    page = max(int(page or 1), 1)
    per_page = max(1, min(int(per_page or 20), 500))

    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        where_clauses = ["(COALESCE(osint_ip, '') != '' OR COALESCE(final_verdict, '') != '')"]
        params: list[Any] = []

        if monitor_type and str(monitor_type).strip().lower() in ("passive", "active"):
            where_clauses.append("COALESCE(monitor_type, 'passive') = ?")
            params.append(str(monitor_type).strip().lower())

        if src_ip and str(src_ip).strip():
            where_clauses.append("LOWER(COALESCE(src_ip, '')) LIKE LOWER(?)")
            params.append(f"%{str(src_ip).strip()}%")

        where_sql = " AND ".join(where_clauses)
        where_sql = f"WHERE {where_sql}" if where_sql else ""

        cursor.execute(f"SELECT COUNT(*) as cnt FROM flows {where_sql}", params)
        total = cursor.fetchone()["cnt"] or 0

        offset = (page - 1) * per_page
        cursor.execute(
            f"""
            SELECT * FROM flows
            {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
            """,
            params + [per_page, offset],
        )
        rows = cursor.fetchall()
        flows = [dict(r) for r in rows]
        conn.close()
        return flows, total


def create_upload_job(job_id: str, filename: str) -> None:
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO upload_jobs (job_id, status, created_at, completed_at, error, filename, result_summary)
            VALUES (?, 'QUEUED', ?, NULL, NULL, ?, NULL)
            """,
            (job_id, datetime.now(timezone.utc).isoformat(), filename),
        )
        conn.commit()
        conn.close()


def update_upload_job(
    job_id: str,
    status: str,
    error: Optional[str] = None,
    result_summary: Optional[Dict[str, Any]] = None,
) -> None:
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        cur = conn.cursor()
        completed_at = datetime.now(timezone.utc).isoformat() if status in ("COMPLETED", "FAILED") else None
        cur.execute(
            """
            UPDATE upload_jobs
            SET status = ?, completed_at = ?, error = ?, result_summary = COALESCE(?, result_summary)
            WHERE job_id = ?
            """,
            (status, completed_at, error, json.dumps(result_summary) if result_summary is not None else None, job_id),
        )
        conn.commit()
        conn.close()


def get_upload_job(job_id: str) -> Optional[Dict[str, Any]]:
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM upload_jobs WHERE job_id = ?", (job_id,))
        row = cur.fetchone()
        conn.close()
    if not row:
        return None
    payload = dict(row)
    try:
        payload["result_summary"] = json.loads(payload["result_summary"] or "{}")
    except Exception:
        payload["result_summary"] = {}
    return payload


def list_upload_jobs(limit: int = 50) -> List[Dict[str, Any]]:
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM upload_jobs ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 500)),))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    for row in rows:
        try:
            row["result_summary"] = json.loads(row.get("result_summary") or "{}")
        except Exception:
            row["result_summary"] = {}
    return rows


def create_alert(flow: Dict[str, Any], reason: str, priority: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    src = str(flow.get("src_ip") or "")
    dst = str(flow.get("dst_ip") or "")
    classification = str(flow.get("classification") or "")
    corr_window = max(1, int(config.ALERT_CORRELATION_WINDOW_MINUTES))
    existing = fetchone(
        """
        SELECT * FROM alerts
        WHERE created_at >= datetime('now', '-' || ? || ' minutes')
          AND LOWER(COALESCE(classification,'')) = LOWER(?)
          AND (LOWER(COALESCE(source_ip,'')) = LOWER(?) OR LOWER(COALESCE(destination_ip,'')) = LOWER(?) OR LOWER(COALESCE(source_ip,'')) = LOWER(?) OR LOWER(COALESCE(destination_ip,'')) = LOWER(?))
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (corr_window, classification, src, src, dst, dst),
    )
    if existing:
        execute(
            "UPDATE alerts SET occurrence_count = COALESCE(occurrence_count,1)+1, last_seen = ?, reason = ?, priority = ? WHERE id = ?",
            (now, reason, priority, existing["id"]),
        )
        return
    correlation_id = f"{classification}:{src or dst}:{int(time.time())}"
    execute(
        """
        INSERT INTO alerts (flow_id, risk_level, classification, created_at, status, reason, priority, correlation_id, source_ip, destination_ip, last_seen, occurrence_count)
        VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, 1)
        """,
        (
            str(flow.get("id") or ""),
            str(flow.get("risk_level") or ""),
            classification,
            now,
            reason,
            priority,
            correlation_id,
            src,
            dst,
            now,
        ),
    )


def list_alerts(status: Optional[str] = None, risk_level: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    where = []
    params: list[Any] = []
    if status:
        where.append("LOWER(status)=LOWER(?)")
        params.append(status)
    if risk_level:
        where.append("LOWER(risk_level)=LOWER(?)")
        params.append(risk_level)
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    return fetchall(f"SELECT * FROM alerts {where_sql} ORDER BY created_at DESC LIMIT ?", tuple(params + [limit]))


def get_alert(alert_id: int) -> Optional[Dict[str, Any]]:
    return fetchone("SELECT * FROM alerts WHERE id = ?", (alert_id,))


def update_alert_status(alert_id: int, status: str) -> bool:
    execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    return True


def register_model_version(version: str, metrics: Dict[str, Any]) -> None:
    execute("UPDATE model_versions SET is_active = 0")
    execute(
        """
        INSERT OR IGNORE INTO model_versions (version, created_at, metrics, is_active)
        VALUES (?, ?, ?, 1)
        """,
        (version, datetime.now(timezone.utc).isoformat(), json.dumps(metrics or {})),
    )
    execute("UPDATE model_versions SET is_active = 1 WHERE version = ?", (version,))


def get_model_versions() -> List[Dict[str, Any]]:
    rows = fetchall("SELECT * FROM model_versions ORDER BY created_at DESC")
    for r in rows:
        try:
            r["metrics"] = json.loads(r.get("metrics") or "{}")
        except Exception:
            r["metrics"] = {}
    return rows


def get_active_model_version() -> Optional[str]:
    row = fetchone("SELECT version FROM model_versions WHERE is_active = 1 ORDER BY id DESC LIMIT 1")
    return row.get("version") if row else None


def run_retention_cleanup(days: int) -> Dict[str, int]:
    with db_lock:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM flows WHERE created_at < datetime('now', '-' || ? || ' days')", (days,))
        flows_deleted = cur.rowcount or 0
        cur.execute("DELETE FROM upload_jobs WHERE created_at < datetime('now', '-' || ? || ' days')", (days,))
        jobs_deleted = cur.rowcount or 0
        cur.execute("DELETE FROM alerts WHERE status = 'RESOLVED' AND created_at < datetime('now', '-' || ? || ' days')", (days,))
        alerts_deleted = cur.rowcount or 0
        conn.commit()
        conn.close()
    return {"flows_deleted": flows_deleted, "jobs_deleted": jobs_deleted, "alerts_deleted": alerts_deleted}


def get_flow_counts_by_monitor_type() -> Dict[str, int]:
    """Return count of flows per monitor_type for debugging."""
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COALESCE(monitor_type, 'passive') as mt, COUNT(*) as cnt
            FROM flows GROUP BY mt
        """)
        result = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()
    return result


def get_dashboard_stats(monitor_type: Optional[str] = None) -> Dict[str, Any]:
    """Get aggregated statistics for dashboard. Optionally filter by monitor_type: 'passive' or 'active'."""
    # Build WHERE for monitor_type (COALESCE so legacy rows without column count as passive)
    if monitor_type and str(monitor_type).strip().lower() in ("passive", "active"):
        where_monitor = " WHERE COALESCE(monitor_type, 'passive') = ? "
        params = [str(monitor_type).strip().lower()]
    else:
        where_monitor = ""
        params = []

    # Passive Traffic Timeline: dedicated store (passive_timeline.db), not flows.db aggregates.
    passive_timeline_precomputed: Optional[List[Dict[str, Any]]] = None
    if monitor_type and str(monitor_type).strip().lower() == "passive":
        passive_timeline_precomputed = get_passive_timeline_points(limit=40)

    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get basic stats
        cursor.execute("""
            SELECT 
                COUNT(*) as total_flows,
                SUM(CASE WHEN is_anomaly THEN 1 ELSE 0 END) as total_anomalies,
                AVG(risk_score) as avg_risk_score
            FROM flows
            """ + where_monitor, params)
        stats = dict(cursor.fetchone())

        total_flows = stats['total_flows'] or 0
        total_anomalies = stats['total_anomalies'] or 0
        avg_risk_score = stats['avg_risk_score'] or 0.0

        # Get attack distribution
        cursor.execute("""
            SELECT classification, COUNT(*) as count
            FROM flows
            """ + where_monitor + """
            GROUP BY classification
        """, params)
        attack_dist = {row['classification']: row['count'] for row in cursor.fetchall()}

        # Get risk distribution
        cursor.execute("""
            SELECT risk_level, COUNT(*) as count
            FROM flows
            """ + where_monitor + """
            GROUP BY risk_level
        """, params)
        risk_dist_db = {row['risk_level']: row['count'] for row in cursor.fetchall()}
        risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        risk_dist.update(risk_dist_db)

        # Timeline
        #
        # Passive (uploads): show points by upload timestamp so the graph updates after each upload
        # (uploads are bursty; "last 1h of flows" can look empty even though uploads exist).
        #
        # Active (live): show last 1 hour of flows grouped by minute.
        if monitor_type and str(monitor_type).strip().lower() == "passive":
            timeline = passive_timeline_precomputed or []
        else:
            # Must use datetime() to normalize ISO 'T' separator / Z suffix / fractional seconds.
            window = "-1 hour"
            timeline_bucket = "substr(timestamp, 1, 16)"  # YYYY-MM-DDTHH:MM

            timeline_where = f"WHERE datetime(timestamp) > datetime('now', '{window}')"
            if where_monitor.strip():
                timeline_where += " AND " + where_monitor.replace("WHERE", "").strip()
            cursor.execute("""
                SELECT 
                    """ + timeline_bucket + """ as hour,
                    COUNT(*) as total,
                    SUM(CASE WHEN is_anomaly THEN 1 ELSE 0 END) as anomalies
                FROM flows
                """ + timeline_where + """
                GROUP BY """ + timeline_bucket + """
                ORDER BY hour
            """, params)
            timeline = [dict(row) for row in cursor.fetchall()]

        # Get protocol distribution
        cursor.execute("""
            SELECT protocol, COUNT(*) as count
            FROM flows
            """ + where_monitor + """
            GROUP BY protocol
        """, params)
        protocols = {row['protocol']: row['count'] for row in cursor.fetchall()}

        # Get top IPs (append AND src_ip IS NOT NULL to monitor filter if present)
        src_where = (where_monitor.strip() + " AND src_ip IS NOT NULL") if where_monitor.strip() else " WHERE src_ip IS NOT NULL"
        cursor.execute("""
            SELECT src_ip, COUNT(*) as count
            FROM flows
            """ + src_where + """
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 10
        """, params)
        top_sources = [{"ip": row['src_ip'], "count": row['count']} for row in cursor.fetchall()]

        dst_where = (where_monitor.strip() + " AND dst_ip IS NOT NULL") if where_monitor.strip() else " WHERE dst_ip IS NOT NULL"
        cursor.execute("""
            SELECT dst_ip, COUNT(*) as count
            FROM flows
            """ + dst_where + """
            GROUP BY dst_ip
            ORDER BY count DESC
            LIMIT 10
        """, params)
        top_destinations = [{"ip": row['dst_ip'], "count": row['count']} for row in cursor.fetchall()]

        conn.close()
        
        return {
            "total_flows": total_flows,
            "total_anomalies": total_anomalies,
            "anomaly_rate": round(total_anomalies / max(total_flows, 1) * 100, 1),
            "avg_risk_score": round(avg_risk_score, 3),
            "attack_distribution": attack_dist,
            "risk_distribution": risk_dist,
            "timeline": timeline,
            "protocols": protocols,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
        }


def get_traffic_trends(
    classification: Optional[str] = None,
    risk_level: Optional[str] = None,
    threat_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    points: int = 72,
    monitor_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Return hourly aggregated trends for traffic analysis charts.
    Uses averages/counts so visualization remains stable for large datasets.
    """
    points = max(12, min(points, 500))

    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        where_clauses = []
        params = []

        if monitor_type and str(monitor_type).strip().lower() in ("passive", "active"):
            where_clauses.append("COALESCE(monitor_type, 'passive') = ?")
            params.append(str(monitor_type).strip().lower())

        if classification:
            where_clauses.append("LOWER(COALESCE(classification, '')) = LOWER(?)")
            params.append(classification.strip())
        if risk_level:
            where_clauses.append("LOWER(COALESCE(risk_level, '')) = LOWER(?)")
            params.append(risk_level.strip())
        if threat_type:
            where_clauses.append("LOWER(COALESCE(threat_type, '')) = LOWER(?)")
            params.append(threat_type.strip())
        if src_ip:
            where_clauses.append("LOWER(COALESCE(src_ip, '')) LIKE LOWER(?)")
            params.append(f"%{src_ip.strip()}%")
        if protocol:
            protocol_clean = protocol.strip()
            if protocol_clean.upper() in PROTOCOL_FILTER_VALUES:
                vals = PROTOCOL_FILTER_VALUES[protocol_clean.upper()]
                placeholders = ", ".join("?" for _ in vals)
                where_clauses.append(f"(COALESCE(protocol, '') IN ({placeholders}))")
                params.extend(vals)
            else:
                where_clauses.append("LOWER(COALESCE(protocol, '')) = LOWER(?)")
                params.append(protocol_clean)

        where_sql = " AND ".join(where_clauses)
        where_sql = f"WHERE {where_sql}" if where_sql else ""

        query = f"""
            SELECT
                substr(timestamp, 1, 16) as hour_bucket,
                COUNT(*) as total_flows,
                SUM(CASE WHEN COALESCE(is_anomaly, 0) = 1 THEN 1 ELSE 0 END) as anomaly_flows,
                SUM(CASE WHEN LOWER(COALESCE(classification, '')) != 'benign' THEN 1 ELSE 0 END) as threat_flows,
                AVG(COALESCE(risk_score, 0)) as avg_risk_score,
                AVG(COALESCE(confidence, 0)) as avg_confidence
            FROM flows
            {where_sql}
            GROUP BY hour_bucket
            ORDER BY hour_bucket DESC
            LIMIT ?
        """
        cursor.execute(query, params + [points])
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()

    rows.reverse()

    result_points = []
    for row in rows:
        total = row.get("total_flows", 0) or 0
        anomalies = row.get("anomaly_flows", 0) or 0
        threats = row.get("threat_flows", 0) or 0
        benign = max(0, total - threats)
        result_points.append({
            "hour": row.get("hour_bucket"),
            "total_flows": total,
            "anomaly_flows": anomalies,
            "threat_flows": threats,
            "benign_flows": benign,
            "anomaly_rate": round((anomalies / max(total, 1)) * 100, 2),
            "threat_rate": round((threats / max(total, 1)) * 100, 2),
            "avg_risk_score": float(row.get("avg_risk_score") or 0.0),
            "avg_confidence": float(row.get("avg_confidence") or 0.0),
        })

    return {
        "points": result_points,
        "count": len(result_points),
    }


def delete_old_flows(days: int = 7) -> int:
    """Delete flows older than specified days. Returns deleted count."""
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM flows
            WHERE created_at < datetime('now', '-' || ? || ' days')
        """, (days,))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted


def get_total_flows_count() -> int:
    """Get total number of flows in database."""
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM flows")
        count = cursor.fetchone()[0]
        conn.close()
        return count


def get_anomaly_data(top_n: int = 50) -> Dict[str, Any]:
    """
    Return anomaly-focused data from uploaded flows.
    Treat rows as anomaly if:
    - is_anomaly = 1, OR
    - classification is not BENIGN.
    """
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        where_clause = """
            (COALESCE(is_anomaly, 0) = 1 OR LOWER(COALESCE(classification, '')) != 'benign')
        """

        cursor.execute(f"SELECT COUNT(*) as cnt FROM flows WHERE {where_clause}")
        total_anomalies = cursor.fetchone()["cnt"] or 0

        cursor.execute(f"""
            SELECT
                SUM(CASE WHEN anomaly_score >= 0.9 THEN 1 ELSE 0 END) as r_09_10,
                SUM(CASE WHEN anomaly_score >= 0.8 AND anomaly_score < 0.9 THEN 1 ELSE 0 END) as r_08_09,
                SUM(CASE WHEN anomaly_score >= 0.7 AND anomaly_score < 0.8 THEN 1 ELSE 0 END) as r_07_08,
                SUM(CASE WHEN anomaly_score >= 0.6 AND anomaly_score < 0.7 THEN 1 ELSE 0 END) as r_06_07,
                SUM(CASE WHEN anomaly_score >= 0.5 AND anomaly_score < 0.6 THEN 1 ELSE 0 END) as r_05_06,
                SUM(CASE WHEN anomaly_score < 0.5 OR anomaly_score IS NULL THEN 1 ELSE 0 END) as r_lt_05
            FROM flows
            WHERE {where_clause}
        """)
        ranges = dict(cursor.fetchone())
        score_distribution = {
            "0.9-1.0": ranges.get("r_09_10", 0) or 0,
            "0.8-0.9": ranges.get("r_08_09", 0) or 0,
            "0.7-0.8": ranges.get("r_07_08", 0) or 0,
            "0.6-0.7": ranges.get("r_06_07", 0) or 0,
            "0.5-0.6": ranges.get("r_05_06", 0) or 0,
            "< 0.5": ranges.get("r_lt_05", 0) or 0,
        }

        cursor.execute(f"""
            SELECT classification, COUNT(*) as count
            FROM flows
            WHERE {where_clause}
            GROUP BY classification
            ORDER BY count DESC
        """)
        attack_breakdown = {
            (row["classification"] if row["classification"] else "Unknown"): row["count"]
            for row in cursor.fetchall()
        }

        cursor.execute(f"""
            SELECT *
            FROM flows
            WHERE {where_clause}
            ORDER BY anomaly_score DESC
            LIMIT ?
        """, (top_n,))
        top_anomalies = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return {
            "total_anomalies": total_anomalies,
            "top_anomalies": top_anomalies,
            "score_distribution": score_distribution,
            "attack_breakdown": attack_breakdown,
        }


def get_threat_data(
    page: int = 1,
    per_page: int = 20,
    classification: Optional[str] = None,
    risk_level: Optional[str] = None,
    src_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    monitor_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Return threat data (all attacks/anomalies) with optional filters + pagination.
    Threat condition:
    - is_anomaly = 1, OR
    - classification != BENIGN
    monitor_type: 'passive', 'active', or None for combined.
    """
    with db_lock:
        conn = _connect_with_retry(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        where_clauses = [
            "(COALESCE(is_anomaly, 0) = 1 OR LOWER(COALESCE(classification, '')) != 'benign')"
        ]
        params = []

        if monitor_type and str(monitor_type).strip().lower() in ("passive", "active"):
            where_clauses.append("COALESCE(monitor_type, 'passive') = ?")
            params.append(str(monitor_type).strip().lower())

        if classification:
            where_clauses.append("LOWER(COALESCE(classification, '')) = LOWER(?)")
            params.append(classification.strip())
        if risk_level:
            where_clauses.append("LOWER(COALESCE(risk_level, '')) = LOWER(?)")
            params.append(risk_level.strip())
        if src_ip:
            where_clauses.append("LOWER(COALESCE(src_ip, '')) LIKE LOWER(?)")
            params.append(f"%{src_ip.strip()}%")
        if protocol:
            where_clauses.append("LOWER(COALESCE(protocol, '')) = LOWER(?)")
            params.append(protocol.strip())

        where_sql = " AND ".join(where_clauses)

        cursor.execute(f"SELECT COUNT(*) as cnt FROM flows WHERE {where_sql}", params)
        total_threats = cursor.fetchone()["cnt"] or 0

        cursor.execute(f"""
            SELECT
                SUM(CASE WHEN anomaly_score >= 0.9 THEN 1 ELSE 0 END) as r_09_10,
                SUM(CASE WHEN anomaly_score >= 0.8 AND anomaly_score < 0.9 THEN 1 ELSE 0 END) as r_08_09,
                SUM(CASE WHEN anomaly_score >= 0.7 AND anomaly_score < 0.8 THEN 1 ELSE 0 END) as r_07_08,
                SUM(CASE WHEN anomaly_score >= 0.6 AND anomaly_score < 0.7 THEN 1 ELSE 0 END) as r_06_07,
                SUM(CASE WHEN anomaly_score >= 0.5 AND anomaly_score < 0.6 THEN 1 ELSE 0 END) as r_05_06,
                SUM(CASE WHEN anomaly_score < 0.5 OR anomaly_score IS NULL THEN 1 ELSE 0 END) as r_lt_05
            FROM flows
            WHERE {where_sql}
        """, params)
        ranges = dict(cursor.fetchone())
        score_distribution = {
            "0.9-1.0": ranges.get("r_09_10", 0) or 0,
            "0.8-0.9": ranges.get("r_08_09", 0) or 0,
            "0.7-0.8": ranges.get("r_07_08", 0) or 0,
            "0.6-0.7": ranges.get("r_06_07", 0) or 0,
            "0.5-0.6": ranges.get("r_05_06", 0) or 0,
            "< 0.5": ranges.get("r_lt_05", 0) or 0,
        }

        cursor.execute(f"""
            SELECT classification, COUNT(*) as count
            FROM flows
            WHERE {where_sql}
            GROUP BY classification
            ORDER BY count DESC
        """, params)
        attack_breakdown = {
            (row["classification"] if row["classification"] else "Unknown"): row["count"]
            for row in cursor.fetchall()
        }

        offset = (page - 1) * per_page
        cursor.execute(f"""
            SELECT *
            FROM flows
            WHERE {where_sql}
            ORDER BY anomaly_score DESC, risk_score DESC
            LIMIT ? OFFSET ?
        """, params + [per_page, offset])
        threats = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return {
            "total_anomalies": total_threats,
            "top_anomalies": threats,
            "score_distribution": score_distribution,
            "attack_breakdown": attack_breakdown,
            "total": total_threats,
            "page": page,
            "per_page": per_page,
            "total_pages": (total_threats + per_page - 1) // per_page,
        }
