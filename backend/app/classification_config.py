"""
Classification criteria, thresholds, and CVE mapping for threat/safe labeling.
Single source of truth for: risk levels, anomaly buckets, threat types, and CVE references.
"""

# ─── Risk level thresholds (risk_score in [0, 1]) ─────────────────────────────
RISK_THRESHOLDS = {
    "Critical": 0.8,   # risk > 0.8
    "High": 0.6,       # risk > 0.6
    "Medium": 0.3,     # risk > 0.3
    "Low": 0.0,        # else
}

def risk_level_from_score(risk: float) -> str:
    if risk > RISK_THRESHOLDS["Critical"]:
        return "Critical"
    if risk > RISK_THRESHOLDS["High"]:
        return "High"
    if risk > RISK_THRESHOLDS["Medium"]:
        return "Medium"
    return "Low"


# ─── Unsupervised anomaly → threat label (when supervised says BENIGN but IF says anomaly) ───
# Fallback when feature-based inference does not match any pattern.
ANOMALY_LABEL_THRESHOLDS = {
    "DDoS": 0.8,
    "Bot": 0.6,
    "Anomaly": 0.0,
}

def _safe_float(v, default=0.0):
    if v is None or (hasattr(v, "__float__") and str(v) in ("nan", "inf", "-inf")):
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        return default

def _safe_int(v, default=0):
    if v is None or (hasattr(v, "__float__") and str(v) in ("nan", "inf", "-inf")):
        return default
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default

def infer_anomaly_threat_type(flow_features: dict, anomaly_score: float) -> str:
    """
    Infer the most likely threat type from flow behavior when the flow is flagged as
    anomalous by the unsupervised model. Uses flow-level features + anomaly_score so
    we assign a specific type (DDoS, Bot, PortScan, etc.) instead of generic "Anomaly"
    whenever possible.
    """
    duration = _safe_float(flow_features.get("duration") or flow_features.get("flow_duration"), 0.0)
    flow_bytes_s = _safe_float(flow_features.get("flow_bytes_per_sec") or flow_features.get("flow_byts_s"), 0.0)
    flow_pkts_s = _safe_float(flow_features.get("flow_packets_per_sec") or flow_features.get("flow_pkts_s"), 0.0)
    tot_fwd = _safe_int(flow_features.get("total_fwd_packets") or flow_features.get("tot_fwd_pkts"), 0)
    tot_bwd = _safe_int(flow_features.get("total_bwd_packets") or flow_features.get("tot_bwd_pkts"), 0)
    totlen_fwd = _safe_float(flow_features.get("total_length_fwd") or flow_features.get("totlen_fwd_pkts"), 0.0)
    totlen_bwd = _safe_float(flow_features.get("total_length_bwd") or flow_features.get("totlen_bwd_pkts"), 0.0)
    dst_port = _safe_int(flow_features.get("dst_port"), -1)
    if dst_port == -1:
        dst_port = _safe_int(flow_features.get("Destination Port"), -1)
    src_port = _safe_int(flow_features.get("src_port"), -1)
    if src_port == -1:
        src_port = _safe_int(flow_features.get("Source Port"), -1)
    # Protocol can be string ("TCP") or numeric (6, 17) from CSV/DataFrame - normalize to string
    _p = flow_features.get("protocol") or flow_features.get("Protocol") or ""
    if hasattr(_p, "upper"):
        proto = str(_p).strip().upper()
    else:
        proto = str(_p).strip() if _p is not None else ""
    # Map common protocol numbers to names for rule matching
    if proto in ("6", "17", "1"):
        proto = {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(proto, proto)
    syn_cnt = _safe_int(flow_features.get("syn_flag_cnt") or flow_features.get("SYN Flag Count"), 0)
    tot_pkts = tot_fwd + tot_bwd
    total_bytes = totlen_fwd + totlen_bwd

    # ─── Port scan: few packets, probe-like ───
    if 1 <= tot_pkts <= 6:
        if syn_cnt >= 1 or duration < 3.0:
            return "PortScan"

    # ─── Brute force: service ports 21,22,23,3389,445, TCP ───
    if proto in ("TCP", "") and dst_port in (21, 22, 23, 3389, 445):
        if 2 <= tot_pkts <= 300 and (duration < 180 or duration == 0):
            return "Brute Force"

    # ─── DDoS: high rate or volume (use lower thresholds to catch more) ───
    if flow_pkts_s > 1500 or flow_bytes_s > 1e6:
        return "DDoS"
    if tot_pkts > 500 and duration >= 0 and duration < 15:
        return "DDoS"
    if total_bytes > 5e6 and duration < 60:
        return "DDoS"
    if anomaly_score > 0.85 and (flow_pkts_s > 200 or tot_pkts > 100):
        return "DDoS"

    # ─── Web attack: HTTP/HTTPS with substantial data ───
    if dst_port in (80, 443) and proto in ("TCP", ""):
        if total_bytes > 20000 and tot_pkts >= 4:
            return "Web Attack"

    # ─── Heartbleed: 443, small packet count, mid-size packets ───
    if dst_port == 443 and 2 <= tot_pkts <= 25:
        avg_len = total_bytes / max(tot_pkts, 1)
        if 50 <= avg_len <= 300:
            return "Heartbleed"

    # ─── Bot: high rate or UDP with many packets (avoid over-flagging generic HTTPS) ───
    # Strong Bot-like: very high packet rate on any non-trivial flow, but ignore common web ports.
    if flow_pkts_s > 200 and tot_pkts >= 8 and dst_port not in (80, 443):
        return "Bot"
    # UDP-heavy anomalies are often scanners/bots.
    if proto == "UDP" and tot_pkts > 20 and anomaly_score > 0.4:
        return "Bot"
    # Only call it Bot for high anomaly score + enough packets, and avoid auto-labeling moderate HTTPS flows.
    if anomaly_score > 0.75 and tot_pkts >= 15 and dst_port not in (80, 443):
        return "Bot"

    # ─── Infiltration: non-common ports on both sides, meaningful activity (avoid flagging normal HTTPS) ───
    common_ports = (21, 22, 23, 80, 443, 3389, 445)
    src_is_common = src_port in common_ports
    dst_is_common = dst_port in common_ports
    if (not src_is_common) and (not dst_is_common) and src_port > 0 and dst_port > 0:
        if tot_pkts >= 4 and total_bytes > 500 and anomaly_score > 0.55:
            return "Infiltration"

    # ─── Score-based fallback: prefer DDoS/Bot over generic Anomaly (with HTTPS safety guard) ───
    if anomaly_score > ANOMALY_LABEL_THRESHOLDS["DDoS"]:
        return "DDoS"
    if anomaly_score > ANOMALY_LABEL_THRESHOLDS["Bot"]:
        # For high anomaly scores, allow Bot as a generic label, but avoid common web ports
        # unless the anomaly is extreme (to limit false positives on normal HTTPS traffic).
        if dst_port not in (80, 443) or anomaly_score > 0.9:
            return "Bot"
    if tot_pkts <= 8 and tot_pkts >= 1:
        return "PortScan"
    return "Anomaly"


def anomaly_label_from_score(anom_score: float) -> str:
    """Legacy: label from score only. Prefer infer_anomaly_threat_type() with flow features."""
    if anom_score > ANOMALY_LABEL_THRESHOLDS["DDoS"]:
        return "DDoS"
    if anom_score > ANOMALY_LABEL_THRESHOLDS["Bot"]:
        return "Bot"
    return "Anomaly"


# ─── Risk formula weights (decision_service) ──────────────────────────────────
# Benign: risk = anomaly_score * 0.6
# Threat (supervised): risk = (confidence * 0.7) + (anomaly_score * 0.3)
# Threat (unsupervised-only): risk = (pseudo_conf * 0.6) + (anomaly_score * 0.4) + 0.15


# ─── Threat type → CVE and description (for “classified according to which CVE”) ───
# Maps classification label (as used in model/UI) to CVE refs and short reason.
# BENIGN = safe; others = threat with optional CVE(s).
THREAT_CVE_MAP = {
    "BENIGN": {
        "threat_type": "Normal",
        "cve_refs": [],
        "description": "Normal traffic; no threat indicators.",
    },
    "Benign": {
        "threat_type": "Normal",
        "cve_refs": [],
        "description": "Normal traffic; no threat indicators.",
    },
    "DDoS": {
        "threat_type": "Denial of Service",
        "cve_refs": ["CVE-2020-5902", "CVE-2018-1050"],
        "description": "DDoS/DoS pattern; may relate to known amplification or service abuse.",
    },
    "Bot": {
        "threat_type": "Botnet / Malware",
        "cve_refs": ["CVE-2016-10709", "CVE-2023-44487"],
        "description": "Bot-like or automated malicious behavior.",
    },
    "Anomaly": {
        "threat_type": "Unclassified Anomaly",
        "cve_refs": [],
        "description": "Behavioral anomaly; no specific CVE (zero-day or unknown pattern).",
    },
    "PortScan": {
        "threat_type": "Reconnaissance",
        "cve_refs": [],
        "description": "Port scan / reconnaissance (no single CVE; activity-based).",
    },
    "Brute Force": {
        "threat_type": "Brute Force",
        "cve_refs": ["CVE-2019-11510", "CVE-2017-5638"],
        "description": "Brute-force or credential abuse pattern.",
    },
    "BruteForce": {
        "threat_type": "Brute Force",
        "cve_refs": ["CVE-2019-11510", "CVE-2017-5638"],
        "description": "Brute-force or credential abuse pattern.",
    },
    "Web Attack": {
        "threat_type": "Web Application Attack",
        "cve_refs": ["CVE-2017-5638", "CVE-2018-11776"],
        "description": "Web application attack (e.g. RCE, injection).",
    },
    "Infiltration": {
        "threat_type": "Infiltration",
        "cve_refs": ["CVE-2017-0144"],
        "description": "Infiltration / lateral movement pattern.",
    },
    "Heartbleed": {
        "threat_type": "Heartbleed (TLS)",
        "cve_refs": ["CVE-2014-0160"],
        "description": "OpenSSL Heartbleed; TLS heartbeat read overrun.",
    },
    "DoS": {
        "threat_type": "Denial of Service",
        "cve_refs": ["CVE-2020-5902", "CVE-2018-1050"],
        "description": "Denial-of-service pattern.",
    },
    "DoS GoldenEye": {
        "threat_type": "Denial of Service",
        "cve_refs": ["CVE-2020-5902"],
        "description": "DoS GoldenEye / HTTP flood pattern.",
    },
    "DoS Hulk": {
        "threat_type": "Denial of Service",
        "cve_refs": ["CVE-2020-5902"],
        "description": "DoS Hulk / HTTP flood pattern.",
    },
    "DoS SlowHTTPTest": {
        "threat_type": "Denial of Service",
        "cve_refs": ["CVE-2018-1050"],
        "description": "Slow HTTP DoS pattern.",
    },
    "FTP-Patator": {
        "threat_type": "Brute Force",
        "cve_refs": ["CVE-2019-11510"],
        "description": "FTP brute-force pattern.",
    },
    "SSH-Patator": {
        "threat_type": "Brute Force",
        "cve_refs": ["CVE-2019-11510"],
        "description": "SSH brute-force pattern.",
    },
}

def get_threat_info(classification: str) -> dict:
    """Return threat_type, cve_refs, description for a classification label. Handles unknown labels."""
    key = classification.strip() if classification else ""
    info = THREAT_CVE_MAP.get(key) or THREAT_CVE_MAP.get(key.upper())
    if info:
        return {
            "threat_type": info["threat_type"],
            "cve_refs": list(info["cve_refs"]),
            "description": info["description"],
        }
    # Unknown attack type from model
    return {
        "threat_type": classification or "Unknown",
        "cve_refs": [],
        "description": f"Classified as '{classification}'; no CVE mapping (behavioral or custom label).",
    }


def build_classification_reason(
    classification: str,
    is_supervised: bool,
    confidence: float,
    anomaly_score: float,
    risk_level: str,
) -> str:
    """Build human-readable reason why flow was classified as threat/safe and risk level."""
    threat_info = get_threat_info(classification)
    cve_part = ""
    if threat_info["cve_refs"]:
        cve_part = f" CVE(s): {', '.join(threat_info['cve_refs'])}."
    else:
        cve_part = " No CVE (behavioral/pattern-based)."

    if classification.upper() == "BENIGN" or threat_info["threat_type"] == "Normal":
        return (
            f"Safe: {threat_info['description']} "
            f"Anomaly score: {anomaly_score:.0%}; risk: {risk_level}."
        )

    if is_supervised:
        return (
            f"Threat: {threat_info['threat_type']}. "
            f"Supervised classification: {classification} (confidence {confidence:.0%}). "
            f"Anomaly score: {anomaly_score:.0%}.{cve_part} "
            f"Risk: {risk_level}."
        )
    return (
        f"Threat: {threat_info['threat_type']}. "
        f"Unsupervised anomaly (score {anomaly_score:.0%}) → {classification}.{cve_part} "
        f"Risk: {risk_level}."
    )
