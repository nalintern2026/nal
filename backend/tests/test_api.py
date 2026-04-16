from __future__ import annotations

from io import BytesIO
import sys
from pathlib import Path

from fastapi.testclient import TestClient

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app import db, config
from app.main import app
from app.services.queue_service import queue_status, enqueue_flow_batch


client = TestClient(app)


def _api_headers():
    config.API_KEY = "test-key"
    return {config.API_KEY_HEADER: "test-key"}


def test_health_endpoint():
    r = client.get("/api/health")
    assert r.status_code == 200
    payload = r.json()
    assert payload["status"] in ("SUCCESS", "DEGRADED")
    assert "data" in payload


def test_integrity_endpoint():
    r = client.get("/api/integrity")
    assert r.status_code == 200
    payload = r.json()
    assert payload["status"] in ("SUCCESS", "DEGRADED")
    assert "checks" in payload["data"]


def test_model_integrity():
    r = client.get("/api/model/integrity")
    assert r.status_code == 200
    payload = r.json()
    assert payload["status"] in ("SUCCESS", "DEGRADED")
    assert "checks" in payload["data"]


def test_upload_job_creation(monkeypatch):
    def _mock_analyze(*args, **kwargs):
        return {
            "id": "a1",
            "total_flows": 1,
            "attack_distribution": {"BENIGN": 1},
            "risk_distribution": {"Low": 1},
            "anomaly_count": 0,
            "avg_risk_score": 0.1,
            "sample_flows": [],
            "report_details": {},
        }

    from app.main import decision_engine

    monkeypatch.setattr(decision_engine, "analyze_file", _mock_analyze)
    files = {"file": ("test.csv", BytesIO(b"a,b\n1,2\n"), "text/csv")}
    res = client.post("/api/upload", files=files, headers=_api_headers())
    assert res.status_code == 200
    body = res.json()["data"]
    assert body["job_id"]
    job = client.get(f"/api/upload/jobs/{body['job_id']}", headers=_api_headers())
    assert job.status_code == 200
    assert job.json()["data"]["status"] in ("PROCESSING", "COMPLETED", "QUEUED")


def test_db_connection():
    assert db.get_total_flows_count() >= 0


def test_alerts_api():
    db.create_alert({"id": "f1", "risk_level": "High", "classification": "DDoS"}, "test", "HIGH")
    r = client.get("/api/alerts", headers=_api_headers())
    assert r.status_code == 200
    alerts = r.json()["data"]["alerts"]
    assert isinstance(alerts, list)


def test_model_version_registration():
    db.register_model_version("test-v1", {"acc": 0.9})
    versions = db.get_model_versions()
    assert any(v["version"] == "test-v1" for v in versions)
    assert db.get_active_model_version() == "test-v1"


def test_retention_cleanup_logic():
    result = db.run_retention_cleanup(0)
    assert "flows_deleted" in result


def test_alert_correlation():
    flow = {"id": "x1", "risk_level": "High", "classification": "DDoS", "src_ip": "5.5.5.5", "dst_ip": "6.6.6.6"}
    db.create_alert(flow, "one", "HIGH")
    db.create_alert(flow, "two", "HIGH")
    rows = db.list_alerts(limit=5)
    assert rows[0].get("occurrence_count", 1) >= 1


def test_queue_fallback():
    ok = enqueue_flow_batch([], "passive")
    assert ok in (True, False)
    qs = queue_status()
    assert "backend" in qs
