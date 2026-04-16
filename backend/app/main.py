"""
Network Traffic Classification & Anomaly Detection - FastAPI Backend
"""
import os
import json
import uuid
import random
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
import shutil

# Load .env (local dev / docker) so OSINT keys and settings are available.
try:
    from dotenv import load_dotenv  # type: ignore

    _env_path = Path(__file__).resolve().parent.parent.parent / ".env"  # nal/.env
    load_dotenv(dotenv_path=_env_path, override=False)
except Exception:
    # If python-dotenv isn't available or .env missing, continue with raw environment.
    pass

from app.services.decision_service import decision_engine
from app.services.threat_feeds import threat_feed_store
from app.services.model_integrity import evaluate_model_integrity
from app.services.integrity_service import run_integrity_checks
from app.services.flow_queue import wait_for_drain
from app.services.queue_service import queue_status, enqueue_flow_batch
from app import config
from app import db
from app.paths import TEMP_UPLOADS_DIR
from app.utils.response import success, failed, degraded
from app.utils.logger import get_logger

# Start background threat feed downloads (daemon thread, non-blocking)
threat_feed_store.start_background_refresh()

from fastapi import FastAPI, UploadFile, File, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any, Tuple
from starlette.exceptions import HTTPException as StarletteHTTPException

# OSINT routes (dedicated UI page)
from app.osint_routes import router as osint_router

app = FastAPI(
    title="Network Security Intelligence API",
    description="Hybrid ML-based network security intelligence system",
    version="1.0.0",
)
logger = get_logger(__name__)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
db.init_db()
cleanup_info = db.run_retention_cleanup(config.DATA_RETENTION_DAYS)
logger.info("Retention cleanup completed: %s", cleanup_info)
db.register_model_version(
    version=f"rf:{bool(decision_engine.rf_model)}-if:{bool(decision_engine.if_model)}-features:{len(decision_engine.feature_names) if decision_engine.feature_names is not None else 0}",
    metrics={},
)


def _retention_loop() -> None:
    while True:
        try:
            db.run_retention_cleanup(config.DATA_RETENTION_DAYS)
        except Exception as e:
            logger.error("Retention cleanup loop error: %s", e)
        time.sleep(3600)


threading.Thread(target=_retention_loop, daemon=True).start()
if not config.API_KEY:
    logger.error("NETGUARD_API_KEY is not configured. Protected /api endpoints will reject requests.")

# Routes
app.include_router(osint_router)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(_: Request, exc: StarletteHTTPException):
    return JSONResponse(status_code=exc.status_code, content=failed("HTTP_ERROR", str(exc.detail)))


@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, exc: Exception):
    logger.error("Unhandled API exception: %s", exc, exc_info=True)
    return JSONResponse(status_code=500, content=failed("INTERNAL_ERROR", "Internal server error"))


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)
    if not request.url.path.startswith("/api"):
        return await call_next(request)
    # Temporary bypass: keep APIs usable when NETGUARD_API_KEY is not set.
    if not config.API_KEY:
        return await call_next(request)
    if request.url.path in ("/api/health", "/api/model/integrity", "/api/integrity"):
        return await call_next(request)
    provided = request.headers.get(config.API_KEY_HEADER, "")
    if not provided:
        return JSONResponse(status_code=401, content=failed("UNAUTHORIZED", "Missing API key"))
    if provided != config.API_KEY:
        return JSONResponse(status_code=401, content=failed("UNAUTHORIZED", "Invalid API key"))
    return await call_next(request)

# ── In-memory storage (for analysis results only) ────────────────────
# Flow records are now stored in SQLite database (db.py)
analysis_results: Dict[str, Any] = {}

# ── Simulated model metrics (Replace with real metrics if available) ──────
# Ideally load metrics.json from training artifacts
MODEL_METRICS = {
    "random_forest": {
        "name": "Random Forest",
        "accuracy": 0.964,
        "precision": 0.958,
        "recall": 0.951,
        "f1_score": 0.954,
        "confusion_matrix": [
            [4521, 87, 32, 15],
            [62, 3892, 45, 22],
            [28, 51, 2145, 18],
            [12, 19, 25, 1876],
        ],
        "roc_auc": 0.987,
        "classes": ["Benign", "DDoS", "PortScan", "BruteForce"],
    },
    "xgboost": {
        "name": "XGBoost",
        "accuracy": 0.971,
        "precision": 0.965,
        "recall": 0.962,
        "f1_score": 0.963,
        "confusion_matrix": [
            [4580, 45, 22, 8],
            [38, 3950, 25, 8],
            [15, 30, 2180, 17],
            [8, 12, 15, 1897],
        ],
        "roc_auc": 0.992,
        "classes": ["Benign", "DDoS", "PortScan", "BruteForce"],
    },
    "isolation_forest": {
        "name": "Isolation Forest (Anomaly)",
        "accuracy": 0.928,
        "precision": 0.915,
        "recall": 0.932,
        "f1_score": 0.923,
        "confusion_matrix": [
            [8950, 450],
            [320, 4280],
        ],
        "roc_auc": 0.961,
        "classes": ["Normal", "Anomaly"],
    },
}

# ── Attack types and their weights ──────────────────────────────────────
ATTACK_TYPES = {
    "Benign": 0.55,
    "DDoS": 0.15,
    "PortScan": 0.10,
    "BruteForce": 0.07,
    "Web Attack": 0.05,
    "Bot": 0.04,
    "Infiltration": 0.02,
    "Heartbleed": 0.02,
}


def generate_demo_flows(count: int = 200) -> List[Dict[str, Any]]:
    """Generate realistic-looking flow records for demonstration (Fallback)."""
    protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH"]
    src_ips = [
        "192.168.1." + str(i) for i in range(10, 60)
    ] + [
        "10.0.0." + str(i) for i in range(1, 30)
    ]
    dst_ips = [
        "172.16.0." + str(i) for i in range(1, 20)
    ] + [
        "8.8.8.8", "1.1.1.1", "204.79.197.200", "142.250.190.46",
    ]

    flows = []
    types_list = list(ATTACK_TYPES.keys())
    weights = list(ATTACK_TYPES.values())

    for i in range(count):
        attack_type = random.choices(types_list, weights=weights, k=1)[0]
        is_anomaly = attack_type != "Benign"
        anomaly_score = round(random.uniform(0.7, 0.99), 3) if is_anomaly else round(random.uniform(0.01, 0.3), 3)
        confidence = round(random.uniform(0.75, 0.99), 3)
        risk_score = round(
            (anomaly_score * 0.4 + (1 - confidence if is_anomaly else 0) * 0.2 + (0.8 if is_anomaly else 0.1) * 0.4),
            3,
        )

        flow = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(0, 1440))).isoformat(),
            "src_ip": random.choice(src_ips),
            "dst_ip": random.choice(dst_ips),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 22, 53, 8080, 3389, 445, 25, 110]),
            "protocol": random.choice(protocols),
            "duration": round(random.uniform(0.001, 120.0), 3),
            "total_fwd_packets": random.randint(1, 500),
            "total_bwd_packets": random.randint(0, 400),
            "total_length_fwd": random.randint(40, 150000),
            "total_length_bwd": random.randint(0, 120000),
            "flow_bytes_per_sec": round(random.uniform(100, 500000), 2),
            "flow_packets_per_sec": round(random.uniform(1, 5000), 2),
            "classification": attack_type,
            "confidence": confidence,
            "anomaly_score": anomaly_score,
            "risk_score": risk_score,
            "is_anomaly": is_anomaly,
            "risk_level": "Critical" if risk_score > 0.7 else "High" if risk_score > 0.5 else "Medium" if risk_score > 0.3 else "Low",
        }
        flows.append(flow)

    return flows

def load_real_data_sample(limit: int = 500) -> List[Dict[str, Any]]:
    """Load a sample of real data from processed folder, or raw/cic_ids (e.g. after synthetic generation)."""
    project_root = Path(__file__).parent.parent.parent
    processed_path = project_root / "training_pipeline" / "data" / "processed" / "cic_ids" / "flows"
    raw_path = project_root / "training_pipeline" / "data" / "raw" / "cic_ids"
    
    csv_files = list(processed_path.rglob("*.csv")) if processed_path.exists() else []
    if not csv_files and raw_path.exists():
        csv_files = list(raw_path.glob("*.csv"))
    
    if not csv_files:
        print("No real data files found. Using demo data.")
        return generate_demo_flows(limit)
    
    # Use the first available file
    target_file = csv_files[0]
    print(f"Loading initial dashboard data from: {target_file}")
    
    try:
        # Analyze file using our ML engine
        result = decision_engine.analyze_file(str(target_file), "csv")
        if "flows" in result:
            flows = result["flows"]
            # Add timestamps incrementally to simulate timeline (since raw data might not have absolute time)
            base_time = datetime.now()
            for i, flow in enumerate(flows):
                flow["timestamp"] = (base_time - timedelta(minutes=i)).isoformat()
            
            return flows[:limit]
    except Exception as e:
        print(f"Error loading real data: {e}. Using demo data.")
        
    return generate_demo_flows(limit)


# ── Initialize Data ─────────────────────────────────────────────────────
# Start with empty records - data will be populated when users upload files
# To test with demo data, uncomment the line below:
# flow_records = load_real_data_sample(500)


# ── Pydantic Models ─────────────────────────────────────────────────────
class AnalysisResult(BaseModel):
    id: str
    filename: str
    timestamp: str
    total_flows: int
    attack_distribution: Dict[str, int]
    anomaly_count: int
    avg_risk_score: float


# ── Health Check ────────────────────────────────────────────────────────
@app.get("/api/health")
async def health_check():
    model_integrity = evaluate_model_integrity()
    status_payload = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "models_loaded": model_integrity["status"] == "ok",
        "api_key_configured": bool(config.API_KEY),
        "services": {
            "supervised_model": "active" if decision_engine.rf_model else "MODEL_UNAVAILABLE",
            "anomaly_detector": "active" if decision_engine.if_model else "MODEL_UNAVAILABLE",
            "decision_engine": "active" if decision_engine.models_ready else "MODEL_UNAVAILABLE",
            "sbom_scanner": "active (user upload only; no project dependencies)",
        },
        "model_integrity": model_integrity["status"],
        "queue": queue_status(),
    }
    return success(status_payload)


@app.get("/api/model/integrity")
async def model_integrity():
    res = evaluate_model_integrity()
    if res.get("status") != "ok":
        return degraded(res, code="MODEL_DEGRADED", message="Model integrity checks failing")
    return success(res)


@app.get("/api/integrity")
async def integrity():
    res = run_integrity_checks()
    res["queue_status"] = queue_status()
    res["security_mode"] = "API_KEY"
    if res.get("status") != "ok":
        return degraded(res, code="INTEGRITY_DEGRADED", message="One or more integrity checks failed")
    return success(res)


# ── Dashboard Stats ─────────────────────────────────────────────────────
@app.get("/api/dashboard/stats")
async def dashboard_stats(monitor_type: Optional[str] = None):
    """Get dashboard statistics. Optional monitor_type: 'passive' (uploads) or 'active' (realtime)."""
    return success(db.get_dashboard_stats(monitor_type=monitor_type))


# ── Classification criteria (thresholds & CVE mapping) ────────────────────
@app.get("/api/classification/criteria")
async def get_classification_criteria():
    """Return classification criteria, risk thresholds, and threat→CVE mapping for UI/docs."""
    from app.classification_config import (
        RISK_THRESHOLDS,
        ANOMALY_LABEL_THRESHOLDS,
        THREAT_CVE_MAP,
    )
    return {
        "risk_thresholds": RISK_THRESHOLDS,
        "risk_levels": ["Critical", "High", "Medium", "Low"],
        "anomaly_label_thresholds": ANOMALY_LABEL_THRESHOLDS,
        "criteria_summary": {
            "risk": "risk_score > 0.8 → Critical; > 0.6 → High; > 0.3 → Medium; else Low.",
            "unsupervised_override": "If supervised says BENIGN but anomaly detector flags flow: threat type is inferred from flow features (rates, ports, protocol, packet counts). Fallback by anomaly_score only if no pattern matches.",
            "feature_based_inference": "PortScan (few packets, SYN/probe-like); Brute Force (ports 21,22,23,3389,445, TCP); DDoS (very high rate or volume); Web Attack (80/443, high bytes); Heartbleed (443, specific packet pattern); Bot (high rate/UDP); Infiltration (unusual port + activity).",
            "safe": "Classification BENIGN/Benign + low anomaly score = Safe (no CVE).",
            "threat_cve": "Threat types are mapped to representative CVE(s) where applicable; 'Why' is in classification_reason.",
        },
        "threat_cve_map": {
            k: {"threat_type": v["threat_type"], "cve_refs": v["cve_refs"], "description": v["description"]}
            for k, v in THREAT_CVE_MAP.items()
        },
    }


# ── Traffic Flows ────────────────────────────────────────────────────────
@app.get("/api/traffic/flows")
async def get_flows(
    page: int = 1,
    per_page: int = 20,
    classification: Optional[str] = None,
    risk_level: Optional[str] = None,
    threat_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    monitor_type: Optional[str] = None,
):
    flows, total = db.get_flows(
        page=page,
        per_page=per_page,
        classification=classification,
        risk_level=risk_level,
        threat_type=threat_type,
        src_ip=src_ip,
        protocol=protocol,
        monitor_type=monitor_type,
    )
    
    return success({
        "flows": flows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
    })


@app.get("/api/traffic/trends")
async def get_traffic_trends(
    classification: Optional[str] = None,
    risk_level: Optional[str] = None,
    threat_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    points: int = 72,
    monitor_type: Optional[str] = None,
):
    return success(db.get_traffic_trends(
        classification=classification,
        risk_level=risk_level,
        threat_type=threat_type,
        src_ip=src_ip,
        protocol=protocol,
        points=points,
        monitor_type=monitor_type,
    ))


@app.get("/api/upload/{analysis_id}/flows")
async def get_upload_flows(
    analysis_id: str,
    page: int = 1,
    per_page: int = 200,
):
    """Get paginated flows for one uploaded file analysis."""
    per_page = max(1, min(per_page, 1000))
    flows, total = db.get_flows(
        page=page,
        per_page=per_page,
        analysis_id=analysis_id,
    )
    return success({
        "analysis_id": analysis_id,
        "flows": flows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
        "has_more": (page * per_page) < total,
    })


# ── Anomalies ───────────────────────────────────────────────────────────
@app.get("/api/anomalies")
async def get_anomalies(
    page: int = 1,
    per_page: int = 20,
    classification: Optional[str] = None,
    risk_level: Optional[str] = None,
    src_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    monitor_type: Optional[str] = None,
):
    """Get threat data (all attack/anomaly types) from flow records. monitor_type: passive, active, or combined."""
    per_page = max(1, min(per_page, 200))
    return success(db.get_threat_data(
        page=page,
        per_page=per_page,
        classification=classification,
        risk_level=risk_level,
        src_ip=src_ip,
        protocol=protocol,
        monitor_type=monitor_type,
    ))


# ── Model Performance ────────────────────────────────────────────────────
def _load_training_metrics() -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    """Load metrics from training_pipeline/models/metrics.json if present."""
    metrics_path = Path(__file__).parent.parent.parent / "training_pipeline" / "models" / "metrics.json"
    if metrics_path.exists():
        try:
            with open(metrics_path, "r") as f:
                data = json.load(f)
            models = data.get("models", {}) or {}
            training_info = data.get("training_info", {})
            return models, training_info, "metrics_json"
        except Exception as e:
            print(f"Could not load metrics.json: {e}")
    return {}, {}, "runtime_only"


@app.get("/api/models/metrics")
async def model_metrics():
    models, training_info, source = _load_training_metrics()
    dashboard = db.get_dashboard_stats()

    total_flows = dashboard.get("total_flows", 0) or 0
    total_anomalies = dashboard.get("total_anomalies", 0) or 0
    avg_risk_score = dashboard.get("avg_risk_score", 0) or 0

    # Runtime metrics from actual uploaded/analyzed flow data.
    recent_flows, _ = db.get_flows(page=1, per_page=1000)
    avg_conf = (
        float(sum(f.get("confidence", 0) for f in recent_flows) / max(len(recent_flows), 1))
        if total_flows > 0 else 0.0
    )

    live_metrics = {
        "total_flows": total_flows,
        "total_anomalies": total_anomalies,
        "anomaly_rate": round((total_anomalies / max(total_flows, 1)) * 100, 2),
        "avg_risk_score": avg_risk_score,
        "avg_confidence": round(avg_conf, 4),
        "risk_distribution": dashboard.get("risk_distribution", {}),
    }

    if not training_info:
        training_info = {
            "dataset": "Runtime uploaded flows",
            "total_samples": total_flows,
            "training_samples": 0,
            "test_samples": 0,
            "feature_count": len(decision_engine.feature_names) if decision_engine.feature_names is not None else 0,
            "last_trained": None,
        }

    return success({
        "models": models,
        "training_info": training_info,
        "live_metrics": live_metrics,
        "model_status": {
            "supervised_loaded": bool(decision_engine.rf_model and decision_engine.label_encoder),
            "unsupervised_loaded": bool(decision_engine.if_model),
            "scaler_loaded": bool(decision_engine.scaler),
        },
        "source": source,
    })


# ── File Upload ──────────────────────────────────────────────────────────
def _normalize_filename(name: Optional[str]) -> str:
    """Use basename and strip; handle None or path-like filenames."""
    if not name or not name.strip():
        return ""
    return Path(name.replace("\\", "/")).name.strip()


def _allowed_extension(basename: str) -> Optional[str]:
    """Return allowed extension if file is allowed; check .pcapng before .pcap. Case-insensitive."""
    if not basename:
        return None
    lower = basename.lower()
    if lower.endswith(".pcapng"):
        return "pcapng"
    if lower.endswith(".pcap"):
        return "pcap"
    if lower.endswith(".csv"):
        return "csv"
    return None


# PCAP magic: a1 b2 c3 d4 | d4 c3 b2 a1 | a1 b2 3c 4d | 4d 3c b2 a1
# PCAPNG magic: 0a 0d 0d 0a (first 4 bytes)
def _detect_pcap_magic(path: Path) -> Optional[str]:
    """Read first 8 bytes and return 'pcap', 'pcapng', or None."""
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except Exception:
        return None
    if len(head) < 4:
        return None
    # PCAPNG: first 4 bytes 0x0a 0x0d 0x0d 0x0a
    if head[:4] == bytes([0x0A, 0x0D, 0x0D, 0x0A]):
        return "pcapng"
    # PCAP
    if len(head) >= 4:
        m = int.from_bytes(head[:4], "little")
        mbe = int.from_bytes(head[:4], "big")
        if m in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1):
            return "pcap"
        if mbe in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1):
            return "pcap"
    return None


def _process_upload_job(job_id: str, file_path: str, filename: str, file_size: int, ext: str) -> None:
    db.update_upload_job(job_id, "PROCESSING")
    try:
        file_type = "pcap" if ext in ("pcap", "pcapng") else "csv"
        result = decision_engine.analyze_file(
            file_path,
            file_type,
            include_flows=False,
            source_filename=filename,
            on_chunk_processed=lambda flows: enqueue_flow_batch(flows, monitor_type="passive"),
        )
        wait_for_drain()
        if "error" in result:
            db.update_upload_job(job_id, "FAILED", error=result["error"])
            return
        analysis_results[result["id"]] = result
        db.insert_analysis(
            analysis_id=result["id"],
            filename=filename,
            monitor_type="passive",
            file_size=file_size,
            total_flows=result.get("total_flows", 0),
            anomaly_count=result.get("anomaly_count", 0),
            avg_risk_score=result.get("avg_risk_score", 0),
            attack_distribution=result.get("attack_distribution", {}),
            risk_distribution=result.get("risk_distribution", {}),
            report_details=result.get("report_details", {}),
        )
        db.update_upload_job(
            job_id,
            "COMPLETED",
            result_summary={
                "id": result["id"],
                "filename": filename,
                "total_flows": result.get("total_flows", 0),
                "attack_distribution": result.get("attack_distribution", {}),
                "risk_distribution": result.get("risk_distribution", {}),
                "anomaly_count": result.get("anomaly_count", 0),
                "avg_risk_score": result.get("avg_risk_score", 0),
                "sample_flows": result.get("sample_flows", []),
                "report_details": result.get("report_details", {}),
                "file_size": file_size,
            },
        )
    except Exception as e:
        logger.error("Upload job failed: %s", e)
        db.update_upload_job(job_id, "FAILED", error=str(e))
    finally:
        try:
            p = Path(file_path)
            if p.exists():
                p.unlink()
        except Exception:
            pass


@app.post("/api/upload")
async def upload_file(background_tasks: BackgroundTasks, file: UploadFile = File(..., alias="file")):
    filename = _normalize_filename(file.filename)
    if not filename:
        raise HTTPException(status_code=400, detail="No file provided")

    TEMP_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    file_path = TEMP_UPLOADS_DIR / f"{uuid.uuid4()}_{filename}"
    size = 0
    try:
        with open(file_path, "wb") as f:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > config.UPLOAD_MAX_FILE_SIZE_BYTES:
                    raise HTTPException(status_code=413, detail=f"File too large. Max {config.UPLOAD_MAX_FILE_SIZE_BYTES} bytes")
                f.write(chunk)
        ext = _allowed_extension(filename) or _detect_pcap_magic(file_path)
        if ext is None:
            raise HTTPException(
                status_code=400,
                detail=f"File type not supported (got '{file.filename}'). Allowed: .pcap, .pcapng, .csv (or extension-less pcap/pcapng).",
            )
        job_id = str(uuid.uuid4())[:12]
        db.create_upload_job(job_id, filename)
        background_tasks.add_task(_process_upload_job, job_id, str(file_path), filename, size, ext)
        return success({"job_id": job_id, "status": "QUEUED"})
    except HTTPException:
        if file_path.exists():
            file_path.unlink(missing_ok=True)
        raise
    finally:
        await file.close()


@app.get("/api/upload/jobs/{job_id}")
async def get_upload_job(job_id: str):
    payload = db.get_upload_job(job_id)
    if not payload:
        raise HTTPException(status_code=404, detail="Upload job not found")
    return success(payload)


@app.get("/api/upload/jobs")
async def list_upload_jobs(limit: int = 50):
    return success({"jobs": db.list_upload_jobs(limit=limit)})


@app.get("/api/alerts")
async def alerts(status: Optional[str] = None, risk_level: Optional[str] = None, limit: int = 100):
    return success({"alerts": db.list_alerts(status=status, risk_level=risk_level, limit=limit)})


@app.get("/api/alerts/{alert_id}")
async def alert_by_id(alert_id: int):
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return success(alert)


@app.patch("/api/alerts/{alert_id}")
async def alert_update(alert_id: int, payload: Dict[str, str]):
    status = str(payload.get("status", "")).upper()
    if status not in ("OPEN", "ACKNOWLEDGED", "RESOLVED"):
        raise HTTPException(status_code=400, detail="Invalid status")
    db.update_alert_status(alert_id, status)
    return success({"id": alert_id, "status": status})


@app.get("/api/model/versions")
async def model_versions():
    return success({"versions": db.get_model_versions()})


@app.get("/api/model/active")
async def model_active():
    return success({"active_version": db.get_active_model_version()})


# ── Analysis History ──────────────────────────────────────────────────────
@app.get("/api/history")
async def get_history(limit: int = 100, monitor_type: Optional[str] = None):
    """List all analyses ordered by upload time (newest first). monitor_type: passive, active, or combined."""
    return success({"analyses": db.get_analysis_history(limit=limit, monitor_type=monitor_type)})


@app.get("/api/history/{analysis_id}")
async def get_history_report(analysis_id: str):
    """Get full report for one analysis (metadata + flows)."""
    report = db.get_analysis_report(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return success(report)


# ── Active / Realtime Monitoring ──────────────────────────────────────────
from app.services.realtime_service import realtime_monitor


@app.post("/api/realtime/start")
async def start_realtime_monitor(interface: str = ""):
    """Start active packet monitoring on the given interface. Run backend with sudo for sniffing."""
    if realtime_monitor.running:
        return degraded({"message": "Already running", "state": realtime_monitor.get_status().get("state")}, code="ALREADY_RUNNING", message="Realtime monitor already running")
    realtime_monitor.start(interface or "")
    return success({"status": "started", "interface": interface or "default"})


@app.post("/api/realtime/stop")
async def stop_realtime_monitor():
    """Stop active monitoring."""
    realtime_monitor.stop()
    return success({"status": "stopped"})


@app.get("/api/realtime/status")
async def get_realtime_status():
    """Get monitor status (running, interface, capture count)."""
    status = realtime_monitor.get_status()
    # Add flow counts so UI can verify active flows exist
    try:
        flows_by_type = db.get_flow_counts_by_monitor_type()
        status["flow_counts"] = flows_by_type
    except Exception:
        status["flow_counts"] = {}
    return success(status)


@app.get("/api/threat-feeds/status")
async def get_threat_feed_status():
    """Get status of local threat intelligence feeds."""
    return success(threat_feed_store.get_status())


@app.get("/api/realtime/interfaces")
async def get_realtime_interfaces():
    """List interfaces that Scapy can use for packet capture (avoids 'interface not found' when user selects one)."""
    try:
        from scapy.all import get_if_list
        ifaces = get_if_list()
        return success({"interfaces": sorted(ifaces) if ifaces else ["lo"]})
    except Exception:
        try:
            import psutil
            ifaces = list(psutil.net_if_addrs().keys())
            return success({"interfaces": sorted(ifaces)})
        except Exception:
            return degraded({"interfaces": ["lo", "eth0", "wlan0"]}, code="INTERFACE_LIST_DEGRADED", message="Using fallback interface list")


# ── SBOM Security ────────────────────────────────────────────────────────
# In-memory store for last user SBOM analysis only. No static data and no project
# dependencies are ever used—all SBOM/vulnerability data comes from user-uploaded files.
_user_sbom_result: Optional[Dict[str, Any]] = None


# Max size for SBOM dependency files (5 MB) - process then discard, no permanent storage
SBOM_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


@app.post("/api/security/sbom/analyze")
async def analyze_sbom_file(file: UploadFile = File(..., alias="file")):
    """Analyze user-uploaded dependency file (requirements.txt, package.json, etc.) and return SBOM + vulnerabilities."""
    global _user_sbom_result
    filename = _normalize_filename(file.filename)
    if not filename:
        raise HTTPException(status_code=400, detail="No file provided")

    allowed = (
        ".txt", ".json", "pipfile", "gemfile", "go.mod", "cargo.toml", "cargo.lock",
        "package-lock.json", "yarn.lock", "poetry.lock", "gemfile.lock",
    )
    fn_lower = filename.lower()
    if not any(fn_lower.endswith(ext) or fn_lower == ext.lstrip(".") for ext in allowed):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file. Allowed: requirements.txt, package.json, package-lock.json, yarn.lock, Pipfile, poetry.lock, Gemfile, Gemfile.lock, go.mod, Cargo.toml, Cargo.lock",
        )

    # Validate file size: read in chunks to avoid loading huge files
    size = 0
    chunk_size = 1024 * 1024
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        size += len(chunk)
        if size > SBOM_MAX_FILE_SIZE_BYTES:
            raise HTTPException(
                status_code=400,
                detail=f"File too large. Maximum size is {SBOM_MAX_FILE_SIZE_BYTES // (1024*1024)} MB.",
            )
    await file.seek(0)

    temp_dir = Path(__file__).parent.parent.parent.parent / "temp_uploads"
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / f"{uuid.uuid4()}_{filename}"
    try:
        with open(file_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        from app.services.sbom_service import analyze_dependency_file
        result = analyze_dependency_file(file_path, filename)
        _user_sbom_result = result
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if file_path.exists():
            try:
                file_path.unlink()
            except Exception:
                pass


@app.get("/api/security/sbom")
async def get_sbom():
    """Get SBOM data. Returns user's last analysis only. No project fallback—users must upload their dependency file."""
    global _user_sbom_result
    if _user_sbom_result:
        return {
            "schema": None,
            "format": "CycloneDX",
            "spec_version": "1.6",
            "serial_number": None,
            "document_version": 1,
            "total_components": _user_sbom_result.get("total_components", 0),
            "dependencies_scanned": _user_sbom_result.get("dependencies_scanned", 0),
            "vulnerable_packages_count": _user_sbom_result.get("vulnerable_packages_count", 0),
            "component_scan_status": _user_sbom_result.get("component_scan_status", []),
            "metadata": {
                "timestamp": _user_sbom_result.get("scan_timestamp"),
                "component": {"name": _user_sbom_result.get("filename"), "type": "file"},
                "tools": [{"name": _user_sbom_result.get("scanner", "CycloneDX"), "type": "scanner"}],
            },
            "components": [
                {
                    "bom_ref": c.get("bom_ref"),
                    "name": c.get("name"),
                    "version": c.get("version"),
                    "type": c.get("type", "library"),
                    "ecosystem": c.get("ecosystem", ""),
                    "purl": c.get("purl", ""),
                    "cpe": c.get("cpe", ""),
                    "properties": [],
                }
                for c in _user_sbom_result.get("components", [])
            ],
        }
    return {
        "schema": None,
        "format": "CycloneDX",
        "total_components": 0,
        "dependencies_scanned": 0,
        "vulnerable_packages_count": 0,
        "component_scan_status": [],
        "metadata": {},
        "components": [],
    }


@app.get("/api/security/vulnerabilities")
async def get_vulnerabilities():
    """Get vulnerability scan results. Returns user's last SBOM analysis vulns only. No project fallback."""
    global _user_sbom_result
    if _user_sbom_result:
        return {
            "total_vulnerabilities": _user_sbom_result.get("total_vulnerabilities", 0),
            "dependencies_scanned": _user_sbom_result.get("dependencies_scanned", 0),
            "vulnerable_packages_count": _user_sbom_result.get("vulnerable_packages_count", 0),
            "component_scan_status": _user_sbom_result.get("component_scan_status", []),
            "severity_distribution": _user_sbom_result.get("severity_distribution", {}),
            "vulnerabilities": _user_sbom_result.get("vulnerabilities", []),
            "scan_timestamp": _user_sbom_result.get("scan_timestamp"),
            "scanner": _user_sbom_result.get("scanner", "CycloneDX"),
            "vuln_source": _user_sbom_result.get("vuln_source", "OSV"),
            "warnings": _user_sbom_result.get("warnings", []),
        }
    return {
        "total_vulnerabilities": 0,
        "dependencies_scanned": 0,
        "vulnerable_packages_count": 0,
        "component_scan_status": [],
        "severity_distribution": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0},
        "vulnerabilities": [],
        "scan_timestamp": None,
        "scanner": None,
        "warnings": [],
    }


@app.get("/api/security/sbom/download")
async def download_sbom():
    """Download SBOM as CycloneDX JSON. Returns user's analyzed BOM if available, else 404."""
    global _user_sbom_result
    if _user_sbom_result:
        from fastapi.responses import JSONResponse
        cyclonedx_json = _user_sbom_result.get("cyclonedx_bom_json")
        if cyclonedx_json:
            bom = json.loads(cyclonedx_json)
        else:
            bom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": _user_sbom_result.get("components", []),
                "metadata": {
                    "timestamp": _user_sbom_result.get("scan_timestamp"),
                    "component": {"name": _user_sbom_result.get("filename")},
                    "tools": [{"name": _user_sbom_result.get("scanner", "CycloneDX")}],
                },
            }
        return JSONResponse(content=bom, media_type="application/json")
    raise HTTPException(status_code=404, detail="No SBOM available. Upload and analyze a dependency file first.")


# ── Root ─────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "message": "Network Security Intelligence API",
        "docs": "/docs",
        "version": "1.0.0",
    }
