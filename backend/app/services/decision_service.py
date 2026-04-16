"""
Decision Service for Network Traffic Analysis.
Handles model loading, traffic preprocessing, and hybrid inference (Supervised + Unsupervised).
"""
import os
import shutil
import pickle
import sys
import logging
import subprocess
import uuid
from datetime import datetime, timezone
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Callable, Optional
import ipaddress

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.feature_engineering import clean_data
from app.classification_config import (
    risk_level_from_score,
    infer_anomaly_threat_type,
    get_threat_info,
    build_classification_reason,
)
from app.services.osint import run_osint_checks, compute_final_score, osint_verdict_from_final_score
from app import db, config
from app.paths import (
    SUPERVISED_MODEL_PATH,
    UNSUPERVISED_MODEL_PATH,
    SCALER_PATH,
    LABEL_ENCODER_PATH,
    FEATURE_NAMES_PATH,
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Temp Dir for PCAP processing
TEMP_DIR = PROJECT_ROOT / "temp_processing"
TEMP_DIR.mkdir(exist_ok=True)

# Backend venv bin (for cicflowmeter) — use path relative to this file so it works under sudo
_BACKEND_ROOT = Path(__file__).resolve().parent.parent.parent
_VENV_BIN = _BACKEND_ROOT / ".venv" / "bin"


def _pick_executable(candidates: list[Path | str]) -> str:
    """
    Pick the first runnable executable from candidates.
    - Path candidates must exist, be a file, and be executable.
    - String candidates are returned as-is (used for PATH lookups).
    """
    for c in candidates:
        if isinstance(c, Path):
            try:
                if c.exists() and c.is_file() and os.access(str(c), os.X_OK):
                    return str(c)
            except Exception:
                # If filesystem checks fail, keep searching other candidates.
                continue
        elif isinstance(c, str) and c:
            return c
    raise FileNotFoundError("No executable candidates provided.")


def _find_cicflowmeter() -> str:
    """
    Locate cicflowmeter across environments:
    - Docker image installs console scripts to /usr/local/bin (found via PATH)
    - Local dev may install into backend .venv/bin
    - When running under sudo, PATH can be minimal; prefer explicit paths first
    """
    env_override = os.environ.get("CICFLOWMETER_BIN")
    if env_override:
        return _pick_executable([Path(env_override), env_override])

    exe_dir = Path(sys.executable).resolve().parent
    which_val = shutil.which("cicflowmeter")

    candidates: list[Path | str] = [
        _VENV_BIN / "cicflowmeter",
        _VENV_BIN / "cicflowmeter.exe",
        exe_dir / "cicflowmeter",
    ]
    if which_val:
        candidates.append(which_val)
    candidates.append("cicflowmeter")
    return _pick_executable(candidates)

class DecisionEngine:
    def __init__(self):
        self.rf_model = None
        self.if_model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self._supervised_fallback_logged = False
        self._load_models()

    @property
    def models_ready(self) -> bool:
        feature_ready = self.feature_names is not None and len(self.feature_names) > 0
        return bool(self.rf_model and self.if_model and self.scaler and self.label_encoder and feature_ready)

    def _validate_features(self, df_clean: pd.DataFrame) -> pd.DataFrame:
        if self.feature_names is None:
            raise RuntimeError("MODEL_UNAVAILABLE: feature names artifact missing")
        missing = [f for f in self.feature_names if f not in df_clean.columns]
        if missing:
            raise RuntimeError(
                f"UNKNOWN: input schema mismatch; missing required features: {missing[:15]}"
            )
        return df_clean[self.feature_names]

    def _alert_priority(self, row: dict) -> str:
        risk = float(row.get("risk_score") or 0.0)
        final = float(row.get("final_score") or 0.0)
        feed = float(row.get("feed_score") or 0.0)
        if row.get("risk_level") == "Critical" or final >= 85 or feed >= 80:
            return "CRITICAL"
        if row.get("risk_level") == "High" or final >= 70 or feed >= 50:
            return "HIGH"
        if risk >= 0.4 or final >= 50:
            return "MEDIUM"
        return "LOW"

    def _load_models(self):
        """Load trained models and artifacts from disk."""
        logger.info("Loading models...")
        
        # Supervised Model
        try:
            with open(SUPERVISED_MODEL_PATH, 'rb') as f:
                self.rf_model = pickle.load(f)
        except FileNotFoundError:
            # Common in fresh installs / anomaly-only deployments; don't spam warnings.
            logger.info(f"Supervised model not found at {SUPERVISED_MODEL_PATH}. Skipping.")
        except Exception as e:
            logger.error(f"Error loading supervised model: {e}")

        # Unsupervised Model
        try:
            with open(UNSUPERVISED_MODEL_PATH, 'rb') as f:
                self.if_model = pickle.load(f)
        except FileNotFoundError:
            logger.warning(f"Unsupervised model not found at {UNSUPERVISED_MODEL_PATH}. Skipping.")
        except Exception as e:
            logger.error(f"Error loading unsupervised model: {e}")

        # Artifacts
        try:
            if SCALER_PATH.exists():
                with open(SCALER_PATH, 'rb') as f:
                    self.scaler = pickle.load(f)
            else:
                # Scaling is recommended but may be missing in minimal deployments.
                logger.info("Scaler artifact not found.")

            if LABEL_ENCODER_PATH.exists():
                with open(LABEL_ENCODER_PATH, 'rb') as f:
                    self.label_encoder = pickle.load(f)
                if self.label_encoder is None:
                    logger.info("Label encoder artifact is None. Supervised predictions are disabled.")
                    self._supervised_fallback_logged = True
            else:
                logger.info("Label encoder artifact not found. Supervised predictions are disabled.")
                self._supervised_fallback_logged = True
            
            if FEATURE_NAMES_PATH.exists():
                with open(FEATURE_NAMES_PATH, 'rb') as f:
                    self.feature_names = pickle.load(f)
            
            logger.info("Models loaded successfully.")
        except Exception as e:
            logger.error(f"Error loading artifacts: {e}")

        if not self.models_ready:
            logger.warning("Model pipeline not fully ready. Inference requests will fail fast.")


    def analyze_file(
        self,
        file_path: str,
        file_type: str,
        include_flows: bool = True,
        source_filename: Optional[str] = None,
        on_chunk_processed: Optional[Callable[[list], int]] = None,
        chunk_size: int = 50000
    ) -> dict:
        """
        Analyze a network capture file (PCAP or CSV).
        
        Args:
            file_path: Path to the uploaded file.
            file_type: 'pcap', 'pcapng', or 'csv'.
            
        Returns:
            Analysis results dict.
        """
        process_id = str(uuid.uuid4())[:8]
        display_filename = source_filename or Path(file_path).name
        logger.info(f"Starting analysis {process_id} for file: {file_path}")
        should_cleanup_csv = False
        csv_path = file_path
        try:
            # 1. PCAP/PCAPNG only: convert to CSV with cicflowmeter; then same pipeline as CSV
            if file_type in ['pcap', 'pcapng']:
                csv_path = self._convert_pcap_to_csv(file_path, process_id)
                should_cleanup_csv = True
            # 2. From here on: csv_path is always a CSV (uploaded CSV or converted from pcap). Same flow.

            attack_counts = {}
            risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            protocol_distribution = {}
            anomaly_breakdown = {}
            attack_flow_samples = {}
            top_anomaly_flows = []
            top_risk_flows = []
            rows = [] if include_flows else None
            sample_flows = []
            total_flows = 0
            anomaly_count = 0
            risk_score_sum = 0.0

            def _safe_int(value):
                if value is None or pd.isna(value):
                    return None
                try:
                    return int(float(value))
                except Exception:
                    return None

            def _safe_float(value):
                if value is None or pd.isna(value):
                    return None
                try:
                    return float(value)
                except Exception:
                    return None

            def _top_n_append(items, row, key, limit=10):
                items.append(row)
                items.sort(key=lambda x: x.get(key, 0) or 0, reverse=True)
                if len(items) > limit:
                    del items[limit:]

            def _pick_osint_ip(src_ip_val: str, dst_ip_val: str) -> Optional[str]:
                """Prefer a public IP for OSINT (skip private/reserved)."""
                for candidate in (src_ip_val, dst_ip_val):
                    try:
                        ip_obj = ipaddress.ip_address(str(candidate).strip())
                        if ip_obj.is_global:
                            return str(ip_obj)
                    except Exception:
                        continue
                return None

            has_rows = False
            for chunk in pd.read_csv(csv_path, chunksize=chunk_size, low_memory=False):
                if chunk is None or chunk.empty:
                    continue

                chunk.columns = chunk.columns.str.strip()
                original_timestamps = None
                for ts_col in ('Timestamp', 'timestamp'):
                    if ts_col in chunk.columns:
                        original_timestamps = chunk[ts_col].copy()
                        break

                df_clean = clean_data(chunk)
                if df_clean.empty:
                    continue

                has_rows = True

                if not self.models_ready:
                    raise RuntimeError("MODEL_UNAVAILABLE: model artifacts are missing or incompatible")
                df_features = self._validate_features(df_clean)
                X_scaled = self.scaler.transform(df_features)
                y_pred = self.rf_model.predict(X_scaled)
                y_prob = self.rf_model.predict_proba(X_scaled)
                confidences = np.max(y_prob, axis=1)
                labels = self.label_encoder.inverse_transform(y_pred)
                anomaly_scores_raw = self.if_model.decision_function(X_scaled)
                anomaly_scores = 0.5 - anomaly_scores_raw
                anomaly_scores = np.clip(anomaly_scores, 0, 1)
                is_anomaly = self.if_model.predict(X_scaled) == -1

                chunk_rows = []
                for i in range(len(df_clean)):
                    original_lbl = str(labels[i])
                    lbl = original_lbl
                    conf = float(confidences[i])
                    anom_score = float(anomaly_scores[i])
                    is_anom = bool(is_anomaly[i])

                    # Unsupervised override: infer threat type from flow features + anomaly score (more accurate than score-only buckets)
                    if is_anom and lbl == 'BENIGN':
                        # Build flow feature dict from current row (same names as we use below for row)
                        duration = df_clean.get('Flow Duration', df_clean.get('flow_duration', None)).iloc[i] if 'Flow Duration' in df_clean or 'flow_duration' in df_clean else None
                        flow_bytes_s = df_clean.get('Flow Bytes/s', df_clean.get('flow_byts_s', None)).iloc[i] if 'Flow Bytes/s' in df_clean or 'flow_byts_s' in df_clean else None
                        flow_pkts_s = df_clean.get('Flow Packets/s', df_clean.get('flow_pkts_s', None)).iloc[i] if 'Flow Packets/s' in df_clean or 'flow_pkts_s' in df_clean else None
                        tot_fwd = df_clean.get('Total Fwd Packets', df_clean.get('tot_fwd_pkts', None)).iloc[i] if 'Total Fwd Packets' in df_clean or 'tot_fwd_pkts' in df_clean else None
                        tot_bwd = df_clean.get('Total Bwd Packets', df_clean.get('tot_bwd_pkts', None)).iloc[i] if 'Total Bwd Packets' in df_clean or 'tot_bwd_pkts' in df_clean else None
                        totlen_fwd = df_clean.get('Total Length Fwd Packets', df_clean.get('totlen_fwd_pkts', None)).iloc[i] if 'Total Length Fwd Packets' in df_clean or 'totlen_fwd_pkts' in df_clean else None
                        totlen_bwd = df_clean.get('Total Length Bwd Packets', df_clean.get('totlen_bwd_pkts', None)).iloc[i] if 'Total Length Bwd Packets' in df_clean or 'totlen_bwd_pkts' in df_clean else None
                        dst_port = df_clean.get('Destination Port', df_clean.get('dst_port', None)).iloc[i] if 'Destination Port' in df_clean or 'dst_port' in df_clean else None
                        src_port = df_clean.get('Source Port', df_clean.get('src_port', None)).iloc[i] if 'Source Port' in df_clean or 'src_port' in df_clean else None
                        proto = df_clean.get('Protocol', df_clean.get('protocol', None)).iloc[i] if 'Protocol' in df_clean or 'protocol' in df_clean else None
                        syn_cnt = df_clean.get('SYN Flag Count', df_clean.get('syn_flag_cnt', None)).iloc[i] if 'SYN Flag Count' in df_clean or 'syn_flag_cnt' in df_clean else None
                        flow_features = {
                            "duration": duration, "flow_duration": duration,
                            "flow_bytes_per_sec": flow_bytes_s, "flow_byts_s": flow_bytes_s,
                            "flow_packets_per_sec": flow_pkts_s, "flow_pkts_s": flow_pkts_s,
                            "total_fwd_packets": tot_fwd, "tot_fwd_pkts": tot_fwd,
                            "total_bwd_packets": tot_bwd, "tot_bwd_pkts": tot_bwd,
                            "total_length_fwd": totlen_fwd, "totlen_fwd_pkts": totlen_fwd,
                            "total_length_bwd": totlen_bwd, "totlen_bwd_pkts": totlen_bwd,
                            "dst_port": dst_port, "Destination Port": dst_port,
                            "src_port": src_port, "Source Port": src_port,
                            "protocol": proto, "Protocol": proto,
                            "syn_flag_cnt": syn_cnt, "SYN Flag Count": syn_cnt,
                        }
                        lbl = infer_anomaly_threat_type(flow_features, anom_score)

                    if lbl == 'BENIGN':
                        risk = anom_score * 0.6 if is_anom else 0.0
                    else:
                        risk = (conf * 0.7) + (anom_score * 0.3)

                    risk = float(np.clip(risk, 0, 1))
                    risk_level = risk_level_from_score(risk)
                    is_supervised_threat = not (is_anom and original_lbl == 'BENIGN')
                    threat_info = get_threat_info(lbl)
                    # Ensure threat_type is always set (so UI never shows "undefined")
                    threat_type_val = (threat_info.get("threat_type") or lbl or "Unknown").strip()
                    cve_refs_str = ",".join(threat_info["cve_refs"]) if threat_info.get("cve_refs") else ""
                    classification_reason = build_classification_reason(
                        lbl, is_supervised_threat, conf, anom_score, risk_level
                    )

                    src_ip = df_clean.get('Source IP', df_clean.get('src_ip', '0.0.0.0')).iloc[i] if 'Source IP' in df_clean or 'src_ip' in df_clean else 'N/A'
                    dst_ip = df_clean.get('Destination IP', df_clean.get('dst_ip', '0.0.0.0')).iloc[i] if 'Destination IP' in df_clean or 'dst_ip' in df_clean else 'N/A'
                    proto = df_clean.get('Protocol', df_clean.get('protocol', 'TCP')).iloc[i]

                    src_port = df_clean.get('Source Port', df_clean.get('src_port', None)).iloc[i] if 'Source Port' in df_clean or 'src_port' in df_clean else None
                    dst_port = df_clean.get('Destination Port', df_clean.get('dst_port', None)).iloc[i] if 'Destination Port' in df_clean or 'dst_port' in df_clean else None
                    duration = df_clean.get('Flow Duration', df_clean.get('flow_duration', None)).iloc[i] if 'Flow Duration' in df_clean or 'flow_duration' in df_clean else None
                    flow_bytes_s = df_clean.get('Flow Bytes/s', df_clean.get('flow_byts_s', None)).iloc[i] if 'Flow Bytes/s' in df_clean or 'flow_byts_s' in df_clean else None
                    flow_packets_s = df_clean.get('Flow Packets/s', df_clean.get('flow_pkts_s', None)).iloc[i] if 'Flow Packets/s' in df_clean or 'flow_pkts_s' in df_clean else None
                    tot_fwd_pkts = df_clean.get('Total Fwd Packets', df_clean.get('tot_fwd_pkts', None)).iloc[i] if 'Total Fwd Packets' in df_clean or 'tot_fwd_pkts' in df_clean else None
                    tot_bwd_pkts = df_clean.get('Total Bwd Packets', df_clean.get('tot_bwd_pkts', None)).iloc[i] if 'Total Bwd Packets' in df_clean or 'tot_bwd_pkts' in df_clean else None
                    totlen_fwd = df_clean.get('Total Length Fwd Packets', df_clean.get('totlen_fwd_pkts', None)).iloc[i] if 'Total Length Fwd Packets' in df_clean or 'totlen_fwd_pkts' in df_clean else None
                    totlen_bwd = df_clean.get('Total Length Bwd Packets', df_clean.get('totlen_bwd_pkts', None)).iloc[i] if 'Total Length Bwd Packets' in df_clean or 'totlen_bwd_pkts' in df_clean else None

                    flow_ts = None
                    if original_timestamps is not None:
                        try:
                            orig_idx = df_clean.index[i]
                            raw_ts = original_timestamps.loc[orig_idx]
                            if pd.notna(raw_ts):
                                parsed = pd.Timestamp(raw_ts)
                                if parsed.tzinfo is None:
                                    parsed = parsed.tz_localize('UTC')
                                else:
                                    parsed = parsed.tz_convert('UTC')
                                flow_ts = parsed.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
                        except Exception:
                            flow_ts = None
                    if flow_ts is None:
                        flow_ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + 'Z'

                    row = {
                        "id": str(uuid.uuid4())[:8],
                        "analysis_id": process_id,
                        "upload_filename": display_filename,
                        "src_ip": str(src_ip) if src_ip is not None else "N/A",
                        "dst_ip": str(dst_ip) if dst_ip is not None else "N/A",
                        "src_port": _safe_int(src_port),
                        "dst_port": _safe_int(dst_port),
                        "protocol": str(proto) if proto is not None else "Unknown",
                        "duration": _safe_float(duration),
                        "total_fwd_packets": _safe_int(tot_fwd_pkts),
                        "total_bwd_packets": _safe_int(tot_bwd_pkts),
                        "total_length_fwd": _safe_int(totlen_fwd),
                        "total_length_bwd": _safe_int(totlen_bwd),
                        "flow_bytes_per_sec": _safe_float(flow_bytes_s),
                        "flow_packets_per_sec": _safe_float(flow_packets_s),
                        "timestamp": flow_ts,
                        "classification": lbl,
                        "threat_type": threat_type_val,
                        "cve_refs": cve_refs_str,
                        "classification_reason": classification_reason,
                        "confidence": conf,
                        "anomaly_score": anom_score,
                        "risk_score": risk,
                        "risk_level": risk_level,
                        "is_anomaly": is_anom,
                        "model_version": db.get_active_model_version(),
                    }

                    # ── OSINT validation (only when anomaly detector flags a flow) ──
                    # ml_confidence is interpreted as 0..100 for the final score.
                    if is_anom:
                        ml_confidence = float(np.clip(anom_score, 0, 1)) * 100.0
                        ip_to_check = _pick_osint_ip(row["src_ip"], row["dst_ip"])
                        if ip_to_check:
                            osint = run_osint_checks(ip_to_check)
                            row["osint_ip"] = osint.ip
                            row["abuse_ok"] = bool(osint.abuse_ok)
                            row["abuse_score"] = osint.abuse_score
                            row["vt_ok"] = bool(osint.vt_ok)
                            row["vt_score"] = osint.vt_score
                            row["feed_score"] = osint.feed_score
                            row["feed_sources"] = osint.feed_sources
                            row["osint_error"] = osint.error

                            has_any_osint = osint.abuse_ok or osint.vt_ok or osint.feed_score > 0
                            if not has_any_osint:
                                rf_conf = conf if conf is not None else 0.0
                                final_score, osint_has_data = compute_final_score(
                                    ml_confidence, osint.abuse_score, osint.vt_score,
                                    rf_confidence=rf_conf, feed_score=osint.feed_score,
                                )
                                row["final_score"] = final_score
                                row["final_verdict"] = osint_verdict_from_final_score(final_score, osint_has_data)
                            else:
                                rf_conf = conf if conf is not None else 0.0
                                final_score, osint_has_data = compute_final_score(
                                    ml_confidence, osint.abuse_score, osint.vt_score,
                                    rf_confidence=rf_conf, feed_score=osint.feed_score,
                                )
                                row["final_score"] = final_score
                                row["final_verdict"] = osint_verdict_from_final_score(final_score, osint_has_data)
                            row["explanation"] = {
                                "ml_score": round(ml_confidence, 2),
                                "osint_score": round(float((osint.abuse_score or 0) + (osint.vt_score or 0)) / 2.0, 2),
                                "feed_score": round(float(osint.feed_score or 0), 2),
                                "final_score": round(float(row.get("final_score") or 0), 2),
                                "explanation": (osint.explanation or []) + ["Isolation Forest anomaly detected"],
                            }
                            if row.get("final_verdict"):
                                logger.info(
                                    "OSINT verdict: ip=%s ml_anom=%.3f rf_conf=%.3f abuse=%s vt=%s feeds=%.0f final=%.1f verdict=%s",
                                    row["osint_ip"],
                                    anom_score,
                                    conf if conf is not None else 0.0,
                                    str(row.get("abuse_score")),
                                    str(row.get("vt_score")),
                                    osint.feed_score,
                                    float(row["final_score"] or 0.0),
                                    row.get("final_verdict"),
                                )
                        else:
                            row["osint_ip"] = None
                            row["abuse_ok"] = False
                            row["abuse_score"] = None
                            row["vt_ok"] = False
                            row["vt_score"] = None
                            row["feed_score"] = 0.0
                            row["feed_sources"] = ""
                            row["osint_error"] = "no public ip (skipped)"
                            row["final_score"] = None
                            row["final_verdict"] = "OSINT Skipped"
                            row["explanation"] = {
                                "ml_score": round(ml_confidence, 2),
                                "osint_score": 0.0,
                                "feed_score": 0.0,
                                "final_score": 0.0,
                                "explanation": ["Isolation Forest anomaly detected", "No public IP available for OSINT"],
                            }
                    chunk_rows.append(row)
                    if row.get("risk_level") in ("High", "Critical") or float(row.get("final_score") or 0.0) > float(config.ALERT_FINAL_SCORE_THRESHOLD):
                        db.create_alert(
                            row,
                            reason=row.get("classification_reason") or "Risk threshold exceeded",
                            priority=self._alert_priority(row),
                        )

                    total_flows += 1
                    anomaly_count += 1 if is_anom else 0
                    risk_score_sum += risk
                    risk_dist[risk_level] += 1
                    attack_counts[lbl] = attack_counts.get(lbl, 0) + 1
                    protocol_distribution[row["protocol"]] = protocol_distribution.get(row["protocol"], 0) + 1

                    if is_anom or lbl != "BENIGN":
                        anomaly_breakdown[lbl] = anomaly_breakdown.get(lbl, 0) + 1
                        _top_n_append(top_anomaly_flows, {
                            "id": row["id"],
                            "classification": row["classification"],
                            "threat_type": row["threat_type"],
                            "cve_refs": row["cve_refs"],
                            "classification_reason": row["classification_reason"],
                            "src_ip": row["src_ip"],
                            "dst_ip": row["dst_ip"],
                            "protocol": row["protocol"],
                            "anomaly_score": row["anomaly_score"],
                            "risk_score": row["risk_score"],
                            "risk_level": row["risk_level"],
                        }, "anomaly_score")

                    _top_n_append(top_risk_flows, {
                        "id": row["id"],
                        "classification": row["classification"],
                        "threat_type": row["threat_type"],
                        "cve_refs": row["cve_refs"],
                        "classification_reason": row["classification_reason"],
                        "src_ip": row["src_ip"],
                        "dst_ip": row["dst_ip"],
                        "protocol": row["protocol"],
                        "anomaly_score": row["anomaly_score"],
                        "risk_score": row["risk_score"],
                        "risk_level": row["risk_level"],
                    }, "risk_score")

                    if len(sample_flows) < 10:
                        sample_flows.append(row)

                    attack_sample_key = row["classification"]
                    if attack_sample_key not in attack_flow_samples:
                        attack_flow_samples[attack_sample_key] = []
                    if len(attack_flow_samples[attack_sample_key]) < 5:
                        attack_flow_samples[attack_sample_key].append({
                            "id": row["id"],
                            "classification": row["classification"],
                            "threat_type": row["threat_type"],
                            "cve_refs": row["cve_refs"],
                            "classification_reason": row["classification_reason"],
                            "src_ip": row["src_ip"],
                            "dst_ip": row["dst_ip"],
                            "protocol": row["protocol"],
                            "risk_level": row["risk_level"],
                            "risk_score": row["risk_score"],
                            "anomaly_score": row["anomaly_score"],
                        })

                if on_chunk_processed and chunk_rows:
                    on_chunk_processed(chunk_rows)

                if include_flows and rows is not None:
                    rows.extend(chunk_rows)

            if not has_rows:
                logger.warning("Loaded CSV is empty after cleaning.")
                return {"error": "File is empty or could not be processed."}

            report_details = {
                "protocol_distribution": protocol_distribution,
                "anomaly_breakdown": anomaly_breakdown,
                "risk_breakdown": risk_dist,
                "top_anomaly_flows": top_anomaly_flows,
                "top_risk_flows": top_risk_flows,
                "attack_flow_samples": attack_flow_samples,
            }

            return {
                "id": process_id,
                "filename": display_filename,
                "total_flows": total_flows,
                "attack_distribution": attack_counts,
                "risk_distribution": risk_dist,
                "anomaly_count": anomaly_count,
                "avg_risk_score": (risk_score_sum / total_flows) if total_flows else 0.0,
                "sample_flows": sample_flows,
                "report_details": report_details,
                "flows": rows if include_flows and rows is not None else []
            }
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            state = "MODEL_UNAVAILABLE" if "MODEL_UNAVAILABLE" in str(e) else "UNKNOWN"
            return {"error": str(e), "state": state}
        finally:
            if should_cleanup_csv and os.path.exists(csv_path):
                os.remove(csv_path)

    def classify_flows(self, flows_raw: list) -> list:
        """
        Classify raw flow dicts (from packet capture). Reuses RF, IF, scaler, threat inference.
        flows_raw: list of dicts with src_ip, dst_ip, src_port, dst_port, protocol,
                   duration, total_fwd_packets, total_bwd_packets, total_length_fwd,
                   total_length_bwd, flow_bytes_per_sec, flow_packets_per_sec, syn_flag_count (optional).
        Returns: list of enriched flow dicts with classification, risk_score, etc.
        """
        if not flows_raw:
            return []
        if not self.models_ready:
            raise RuntimeError("MODEL_UNAVAILABLE: model artifacts are missing or incompatible")

        def _safe_int(v):
            if v is None or (isinstance(v, float) and np.isnan(v)):
                return None
            try:
                return int(float(v))
            except Exception:
                return None

        def _safe_float(v):
            if v is None or (isinstance(v, float) and np.isnan(v)):
                return None
            try:
                return float(v)
            except Exception:
                return None

        rows = []
        for f in flows_raw:
            row = {
                "Source IP": f.get("src_ip", "0.0.0.0"),
                "Destination IP": f.get("dst_ip", "0.0.0.0"),
                "Protocol": f.get("protocol", "TCP"),
                "src_port": f.get("src_port", 0),
                "dst_port": f.get("dst_port", 0),
                "protocol": f.get("protocol_num", 6),
                "flow_duration": f.get("flow_duration", 0),
                "flow_byts_s": f.get("flow_byts_s", 0),
                "flow_pkts_s": f.get("flow_pkts_s", 0),
                "fwd_pkts_s": f.get("fwd_pkts_s", 0),
                "bwd_pkts_s": f.get("bwd_pkts_s", 0),
                "tot_fwd_pkts": f.get("tot_fwd_pkts", 0),
                "tot_bwd_pkts": f.get("tot_bwd_pkts", 0),
                "totlen_fwd_pkts": f.get("totlen_fwd_pkts", 0),
                "totlen_bwd_pkts": f.get("totlen_bwd_pkts", 0),
                "fwd_pkt_len_max": f.get("fwd_pkt_len_max", 0),
                "fwd_pkt_len_min": f.get("fwd_pkt_len_min", 0),
                "fwd_pkt_len_mean": f.get("fwd_pkt_len_mean", 0),
                "fwd_pkt_len_std": f.get("fwd_pkt_len_std", 0),
                "bwd_pkt_len_max": f.get("bwd_pkt_len_max", 0),
                "bwd_pkt_len_min": f.get("bwd_pkt_len_min", 0),
                "bwd_pkt_len_mean": f.get("bwd_pkt_len_mean", 0),
                "bwd_pkt_len_std": f.get("bwd_pkt_len_std", 0),
                "pkt_len_max": f.get("pkt_len_max", 0),
                "pkt_len_min": f.get("pkt_len_min", 0),
                "pkt_len_mean": f.get("pkt_len_mean", 0),
                "pkt_len_std": f.get("pkt_len_std", 0),
                "pkt_len_var": f.get("pkt_len_var", 0),
                "fwd_header_len": f.get("fwd_header_len", 0),
                "bwd_header_len": f.get("bwd_header_len", 0),
                "fwd_seg_size_min": f.get("fwd_seg_size_min", 0),
                "fwd_act_data_pkts": f.get("fwd_act_data_pkts", 0),
                "flow_iat_mean": f.get("flow_iat_mean", 0),
                "flow_iat_max": f.get("flow_iat_max", 0),
                "flow_iat_min": f.get("flow_iat_min", 0),
                "flow_iat_std": f.get("flow_iat_std", 0),
                "fwd_iat_tot": f.get("fwd_iat_tot", 0),
                "fwd_iat_max": f.get("fwd_iat_max", 0),
                "fwd_iat_min": f.get("fwd_iat_min", 0),
                "fwd_iat_mean": f.get("fwd_iat_mean", 0),
                "fwd_iat_std": f.get("fwd_iat_std", 0),
                "bwd_iat_tot": f.get("bwd_iat_tot", 0),
                "bwd_iat_max": f.get("bwd_iat_max", 0),
                "bwd_iat_min": f.get("bwd_iat_min", 0),
                "bwd_iat_mean": f.get("bwd_iat_mean", 0),
                "bwd_iat_std": f.get("bwd_iat_std", 0),
                "fwd_psh_flags": f.get("fwd_psh_flags", 0),
                "bwd_psh_flags": f.get("bwd_psh_flags", 0),
                "fwd_urg_flags": f.get("fwd_urg_flags", 0),
                "bwd_urg_flags": f.get("bwd_urg_flags", 0),
                "fin_flag_cnt": f.get("fin_flag_cnt", 0),
                "syn_flag_cnt": f.get("syn_flag_cnt", 0),
                "rst_flag_cnt": f.get("rst_flag_cnt", 0),
                "psh_flag_cnt": f.get("psh_flag_cnt", 0),
                "ack_flag_cnt": f.get("ack_flag_cnt", 0),
                "urg_flag_cnt": f.get("urg_flag_cnt", 0),
                "ece_flag_cnt": f.get("ece_flag_cnt", 0),
                "cwr_flag_count": f.get("cwr_flag_count", 0),
                "down_up_ratio": f.get("down_up_ratio", 0),
                "pkt_size_avg": f.get("pkt_size_avg", 0),
                "init_fwd_win_byts": f.get("init_fwd_win_byts", 0),
                "init_bwd_win_byts": f.get("init_bwd_win_byts", 0),
                "active_max": f.get("active_max", 0),
                "active_min": f.get("active_min", 0),
                "active_mean": f.get("active_mean", 0),
                "active_std": f.get("active_std", 0),
                "idle_max": f.get("idle_max", 0),
                "idle_min": f.get("idle_min", 0),
                "idle_mean": f.get("idle_mean", 0),
                "idle_std": f.get("idle_std", 0),
                "fwd_byts_b_avg": f.get("fwd_byts_b_avg", 0),
                "fwd_pkts_b_avg": f.get("fwd_pkts_b_avg", 0),
                "bwd_byts_b_avg": f.get("bwd_byts_b_avg", 0),
                "bwd_pkts_b_avg": f.get("bwd_pkts_b_avg", 0),
                "fwd_blk_rate_avg": f.get("fwd_blk_rate_avg", 0),
                "bwd_blk_rate_avg": f.get("bwd_blk_rate_avg", 0),
                "fwd_seg_size_avg": f.get("fwd_seg_size_avg", 0),
                "bwd_seg_size_avg": f.get("bwd_seg_size_avg", 0),
                "subflow_fwd_pkts": f.get("subflow_fwd_pkts", 0),
                "subflow_bwd_pkts": f.get("subflow_bwd_pkts", 0),
                "subflow_fwd_byts": f.get("subflow_fwd_byts", 0),
                "subflow_bwd_byts": f.get("subflow_bwd_byts", 0),
            }
            rows.append(row)

        df = pd.DataFrame(rows)
        if df.empty:
            return []

        # Fill NaN in numeric columns so clean_data doesn't drop rows
        for col in df.select_dtypes(include=[np.number]).columns:
            df[col] = df[col].fillna(0)
        df = clean_data(df)
        if df.empty:
            return []

        df_features = self._validate_features(df)
        X_scaled = self.scaler.transform(df_features)
        y_pred = self.rf_model.predict(X_scaled)
        y_prob = self.rf_model.predict_proba(X_scaled)
        confidences = np.max(y_prob, axis=1)
        labels = self.label_encoder.inverse_transform(y_pred)
        anomaly_scores_raw = self.if_model.decision_function(X_scaled)
        anomaly_scores = 0.5 - anomaly_scores_raw
        anomaly_scores = np.clip(anomaly_scores, 0, 1)
        is_anomaly = self.if_model.predict(X_scaled) == -1

        result = []
        for i in range(len(df)):
            original_lbl = str(labels[i])
            lbl = original_lbl
            conf = float(confidences[i])
            anom_score = float(anomaly_scores[i])
            is_anom = bool(is_anomaly[i])

            if is_anom and lbl == "BENIGN":
                r = df.iloc[i]
                flow_features = {
                    "duration": r.get("flow_duration", r.get("Flow Duration", 0)),
                    "flow_bytes_per_sec": r.get("flow_byts_s", r.get("Flow Bytes/s", 0)),
                    "flow_packets_per_sec": r.get("flow_pkts_s", r.get("Flow Packets/s", 0)),
                    "total_fwd_packets": r.get("tot_fwd_pkts", r.get("Total Fwd Packets", 0)),
                    "total_bwd_packets": r.get("tot_bwd_pkts", r.get("Total Backward Packets", 0)),
                    "total_length_fwd": r.get("totlen_fwd_pkts", r.get("Total Length of Fwd Packets", 0)),
                    "total_length_bwd": r.get("totlen_bwd_pkts", r.get("Total Length of Bwd Packets", 0)),
                    "dst_port": r.get("dst_port", r.get("Destination Port")),
                    "protocol": r.get("Protocol", r.get("protocol", "")),
                    "syn_flag_cnt": r.get("syn_flag_cnt", r.get("SYN Flag Count", 0)),
                }
                lbl = infer_anomaly_threat_type(flow_features, anom_score)

            if lbl == "BENIGN":
                risk = anom_score * 0.6 if is_anom else 0.0
            else:
                risk = (conf * 0.7) + (anom_score * 0.3)

            risk = float(np.clip(risk, 0, 1))
            risk_level = risk_level_from_score(risk)
            threat_info = get_threat_info(lbl)
            threat_type_val = (threat_info.get("threat_type") or lbl or "Unknown").strip()
            cve_refs_str = ",".join(threat_info["cve_refs"]) if threat_info.get("cve_refs") else ""
            classification_reason = build_classification_reason(
                lbl, not (is_anom and original_lbl == "BENIGN"), conf, anom_score, risk_level
            )

            r = df.iloc[i]
            row = {
                "id": str(uuid.uuid4())[:8],
                "analysis_id": None,
                "upload_filename": "realtime",
                "src_ip": str(r.get("Source IP", "N/A")),
                "dst_ip": str(r.get("Destination IP", "N/A")),
                "src_port": _safe_int(r.get("src_port", r.get("Source Port"))),
                "dst_port": _safe_int(r.get("dst_port", r.get("Destination Port"))),
                "protocol": str(r.get("Protocol", "Unknown")),
                "duration": _safe_float(r.get("flow_duration", r.get("Flow Duration"))),
                "total_fwd_packets": _safe_int(r.get("tot_fwd_pkts", r.get("Total Fwd Packets"))),
                "total_bwd_packets": _safe_int(r.get("tot_bwd_pkts", r.get("Total Backward Packets"))),
                "total_length_fwd": _safe_int(r.get("totlen_fwd_pkts", r.get("Total Length of Fwd Packets"))),
                "total_length_bwd": _safe_int(r.get("totlen_bwd_pkts", r.get("Total Length of Bwd Packets"))),
                "flow_bytes_per_sec": _safe_float(r.get("flow_byts_s", r.get("Flow Bytes/s"))),
                "flow_packets_per_sec": _safe_float(r.get("flow_pkts_s", r.get("Flow Packets/s"))),
                "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + 'Z',
                "classification": lbl,
                "threat_type": threat_type_val,
                "cve_refs": cve_refs_str,
                "classification_reason": classification_reason,
                "confidence": conf,
                "anomaly_score": anom_score,
                "risk_score": risk,
                "risk_level": risk_level,
                "is_anomaly": is_anom,
                "model_version": db.get_active_model_version(),
            }

            # OSINT validation (only when anomaly detector flags a flow)
            if is_anom:
                ip_to_check = None
                try:
                    for candidate in (row["src_ip"], row["dst_ip"]):
                        ip_obj = ipaddress.ip_address(str(candidate).strip())
                        if ip_obj.is_global:
                            ip_to_check = str(ip_obj)
                            break
                except Exception:
                    ip_to_check = None

                ml_confidence = float(np.clip(anom_score, 0, 1)) * 100.0
                if ip_to_check:
                    osint = run_osint_checks(ip_to_check)
                    row["osint_ip"] = osint.ip
                    row["abuse_ok"] = bool(osint.abuse_ok)
                    row["abuse_score"] = osint.abuse_score
                    row["vt_ok"] = bool(osint.vt_ok)
                    row["vt_score"] = osint.vt_score
                    row["feed_score"] = osint.feed_score
                    row["feed_sources"] = osint.feed_sources
                    row["osint_error"] = osint.error
                    rf_conf = conf if conf is not None else 0.0
                    final_score, osint_has_data = compute_final_score(
                        ml_confidence, osint.abuse_score, osint.vt_score,
                        rf_confidence=rf_conf, feed_score=osint.feed_score,
                    )
                    row["final_score"] = final_score
                    row["final_verdict"] = osint_verdict_from_final_score(final_score, osint_has_data)
                    row["explanation"] = {
                        "ml_score": round(ml_confidence, 2),
                        "osint_score": round(float((osint.abuse_score or 0) + (osint.vt_score or 0)) / 2.0, 2),
                        "feed_score": round(float(osint.feed_score or 0), 2),
                        "final_score": round(float(row.get("final_score") or 0), 2),
                        "explanation": (osint.explanation or []) + ["Isolation Forest anomaly detected"],
                    }
                else:
                    row["osint_ip"] = None
                    row["abuse_ok"] = False
                    row["abuse_score"] = None
                    row["vt_ok"] = False
                    row["vt_score"] = None
                    row["feed_score"] = 0.0
                    row["feed_sources"] = ""
                    row["osint_error"] = "no public ip (skipped)"
                    row["final_score"] = None
                    row["final_verdict"] = "OSINT Skipped"
                    row["explanation"] = {
                        "ml_score": round(ml_confidence, 2),
                        "osint_score": 0.0,
                        "feed_score": 0.0,
                        "final_score": 0.0,
                        "explanation": ["Isolation Forest anomaly detected", "No public IP available for OSINT"],
                    }

            result.append(row)
            if row.get("risk_level") in ("High", "Critical") or float(row.get("final_score") or 0.0) > float(config.ALERT_FINAL_SCORE_THRESHOLD):
                db.create_alert(
                    row,
                    reason=row.get("classification_reason") or "Risk threshold exceeded",
                    priority=self._alert_priority(row),
                )

        return result

    def _convert_pcap_to_csv(self, pcap_path: str, process_id: str) -> str:
        """Run cicflowmeter to convert PCAP to CSV. Uses same Python/venv so the binary is found."""
        output_dir = TEMP_DIR / process_id
        output_dir.mkdir(parents=True, exist_ok=True)
        csv_name = f"{process_id}.csv"
        csv_path = output_dir / csv_name

        try:
            cicflowmeter_bin = _find_cicflowmeter()
        except Exception as e:
            raise RuntimeError(
                "cicflowmeter is required to convert PCAP/PCAPNG to CSV but was not found. "
                "Install it in the environment running the backend (pip install -r backend/requirements.txt) "
                "or set CICFLOWMETER_BIN to the executable path."
            ) from e

        cmd = [cicflowmeter_bin, "-f", pcap_path, "-c", str(csv_path)]
        logger.info(f"Running: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            logger.error(f"cicflowmeter failed: {result.stderr}")
            raise RuntimeError(f"Failed to convert PCAP to CSV: {result.stderr}")
            
        if not csv_path.exists():
             raise RuntimeError("CSV file was not created by cicflowmeter.")
        logger.info("PCAP/PCAPNG conversion done; starting flow analysis (same as CSV path).")
        return str(csv_path)

# Singleton instance
decision_engine = DecisionEngine()
