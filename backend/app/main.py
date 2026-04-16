"""
Network Traffic Classification & Anomaly Detection - FastAPI Backend
"""
import os
import json
import uuid
import random
import glob
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
from app import db

# Start background threat feed downloads (daemon thread, non-blocking)
threat_feed_store.start_background_refresh()

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any, Tuple

# OSINT routes (dedicated UI page)
from app.osint_routes import router as osint_router

app = FastAPI(
    title="Network Security Intelligence API",
    description="Hybrid ML-based network security intelligence system",
    version="1.0.0",
)

# CORS - allow frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
db.init_db()

# Routes
app.include_router(osint_router)

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
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "models_loaded": True,
        "services": {
            "supervised_model": "active" if decision_engine.rf_model else "inactive (no labels)",
            "anomaly_detector": "active" if decision_engine.if_model else "inactive",
            "decision_engine": "active",
            "sbom_scanner": "active (user upload only; no project dependencies)",
        },
    }


# ── Dashboard Stats ─────────────────────────────────────────────────────
@app.get("/api/dashboard/stats")
async def dashboard_stats(monitor_type: Optional[str] = None):
    """Get dashboard statistics. Optional monitor_type: 'passive' (uploads) or 'active' (realtime)."""
    return db.get_dashboard_stats(monitor_type=monitor_type)


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
    
    return {
        "flows": flows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
    }


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
    return db.get_traffic_trends(
        classification=classification,
        risk_level=risk_level,
        threat_type=threat_type,
        src_ip=src_ip,
        protocol=protocol,
        points=points,
        monitor_type=monitor_type,
    )


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
    return {
        "analysis_id": analysis_id,
        "flows": flows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
        "has_more": (page * per_page) < total,
    }


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
    return db.get_threat_data(
        page=page,
        per_page=per_page,
        classification=classification,
        risk_level=risk_level,
        src_ip=src_ip,
        protocol=protocol,
        monitor_type=monitor_type,
    )


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

    return {
        "models": models,
        "training_info": training_info,
        "live_metrics": live_metrics,
        "model_status": {
            "supervised_loaded": bool(decision_engine.rf_model and decision_engine.label_encoder),
            "unsupervised_loaded": bool(decision_engine.if_model),
            "scaler_loaded": bool(decision_engine.scaler),
        },
        "source": source,
    }


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


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(..., alias="file")):
    global flow_records, analysis_results

    filename = _normalize_filename(file.filename)
    if not filename:
        raise HTTPException(status_code=400, detail="No file provided")

    # Save to temp first so we can use magic-byte detection for extension-less files (e.g. pcap chunks)
    temp_dir = Path(__file__).parent.parent.parent.parent / "temp_uploads"
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / f"{uuid.uuid4()}_{filename}"
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    file_size = file_path.stat().st_size if file_path.exists() else None

    ext = _allowed_extension(filename)
    if ext is None:
        ext = _detect_pcap_magic(file_path)
    if ext is None:
        if file_path.exists():
            try:
                file_path.unlink()
            except Exception:
                pass
        raise HTTPException(
            status_code=400,
            detail=f"File type not supported (got '{file.filename}'). Allowed: .pcap, .pcapng, .csv (or extension-less pcap/pcapng).",
        )

    try:
        # Run real analysis; pass 'pcap' for both .pcap and .pcapng (decision_service treats both same)
        file_type = "pcap" if ext in ("pcap", "pcapng") else "csv"
        
        result = decision_engine.analyze_file(
            str(file_path),
            file_type,
            include_flows=False,
            source_filename=filename,
            on_chunk_processed=lambda flows: db.insert_flows(flows, monitor_type="passive"),
        )
        
        if "error" in result:
             raise HTTPException(status_code=500, detail=result["error"])

        analysis_results[result['id']] = result

        # Persist to analysis history (survives refresh)
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
        
        return {
            "status": "success",
            "id": result['id'],
            "filename": filename,
            "total_flows": result.get('total_flows', 0),
            "attack_distribution": result.get('attack_distribution', {}),
            "risk_distribution": result.get('risk_distribution', {}),
            "anomaly_count": result.get('anomaly_count', 0),
            "avg_risk_score": result.get('avg_risk_score', 0),
            "sample_flows": result.get('sample_flows', []),
            "report_details": result.get('report_details', {}),
            "file_size": file_size,
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if file_path.exists():
            try:
                os.remove(file_path)
            except:
                pass


# ── Analysis History ──────────────────────────────────────────────────────
@app.get("/api/history")
async def get_history(limit: int = 100, monitor_type: Optional[str] = None):
    """List all analyses ordered by upload time (newest first). monitor_type: passive, active, or combined."""
    return {"analyses": db.get_analysis_history(limit=limit, monitor_type=monitor_type)}


@app.get("/api/history/{analysis_id}")
async def get_history_report(analysis_id: str):
    """Get full report for one analysis (metadata + flows)."""
    report = db.get_analysis_report(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return report


# ── Active / Realtime Monitoring ──────────────────────────────────────────
from app.services.realtime_service import realtime_monitor


@app.post("/api/realtime/start")
async def start_realtime_monitor(interface: str = ""):
    """Start active packet monitoring on the given interface. Run backend with sudo for sniffing."""
    if realtime_monitor.running:
        return {"status": "error", "message": "Already running"}
    # Run in daemon thread so we never block the event loop
    import threading
    t = threading.Thread(target=realtime_monitor.start, args=(interface or "",), daemon=True)
    t.start()
    return {"status": "started", "interface": interface or "default"}


@app.post("/api/realtime/stop")
async def stop_realtime_monitor():
    """Stop active monitoring."""
    realtime_monitor.stop()
    return {"status": "stopped"}


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
    return status


@app.get("/api/threat-feeds/status")
async def get_threat_feed_status():
    """Get status of local threat intelligence feeds."""
    return threat_feed_store.get_status()


@app.get("/api/realtime/interfaces")
async def get_realtime_interfaces():
    """List interfaces that Scapy can use for packet capture (avoids 'interface not found' when user selects one)."""
    try:
        from scapy.all import get_if_list
        ifaces = get_if_list()
        return {"interfaces": sorted(ifaces) if ifaces else ["lo"]}
    except Exception:
        try:
            import psutil
            ifaces = list(psutil.net_if_addrs().keys())
            return {"interfaces": sorted(ifaces)}
        except Exception:
            return {"interfaces": ["lo", "eth0", "wlan0"]}


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
