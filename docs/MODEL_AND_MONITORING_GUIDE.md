# Model & Monitoring Guide

This document explains how the anomaly detection model works, the thresholds used, and how **Active** vs **Passive** monitoring differ.

---

## 1. Model Overview

The system uses a **hybrid pipeline**:

| Component | Purpose | Status |
|-----------|---------|--------|
| **Isolation Forest (IF)** | Unsupervised anomaly detection | Required |
| **Random Forest (RF)** | Supervised attack classification | Optional (often missing) |
| **Scaler** | Normalizes features for the models | Required |
| **Feature names** | 79 CIC-style flow features | Required |

When the supervised model (RF) is missing, all flows are labeled **BENIGN** by default. The Isolation Forest then flags which of those are actually anomalous, and rule-based logic assigns a threat type.

---

## 2. How Anomalies Are Detected

### 2.1 Isolation Forest

- **Algorithm:** Isolation Forest from scikit-learn
- **Idea:** Anomalies are easier to isolate than normal points. The model builds random trees; flows that need fewer splits to isolate get higher anomaly scores.
- **Output:** For each flow, it returns:
  - `predict()` → **+1** (normal) or **-1** (anomaly)
  - `decision_function()` → raw score (lower = more anomalous)

### 2.2 Threshold (Contamination)

There is **no explicit numeric threshold** like "anomaly_score > 0.7". The decision comes from the model’s **contamination** parameter:

- **`contamination = 0.01`** (1%)
- The model assumes ~1% of the training data are anomalies
- It effectively treats the **top ~1%** of flows (by anomaly score) as anomalies
- A flow is anomalous when: `if_model.predict(X) == -1`

### 2.3 Anomaly Score (0–1)

The raw `decision_function` output is converted for display:

```
anomaly_score = 0.5 - decision_function(X)
anomaly_score = clip(anomaly_score, 0, 1)
```

- Higher score → more anomalous
- Used for risk scoring and threat inference

---

## 3. Risk Scoring

### 3.1 Risk Level Thresholds

| Level | Threshold | Meaning |
|-------|-----------|---------|
| Critical | risk > 0.8 | Very high risk |
| High | risk > 0.6 | High risk |
| Medium | risk > 0.3 | Medium risk |
| Low | risk ≤ 0.3 | Low risk |

### 3.2 Risk Formula

- **BENIGN + not anomalous:** `risk = 0`
- **BENIGN + anomalous:** `risk = anomaly_score × 0.6`
- **Threat (from RF or rules):** `risk = (confidence × 0.7) + (anomaly_score × 0.3)` (or similar)

---

## 4. Threat Type Inference

When the Isolation Forest flags a flow as anomalous but the label is still BENIGN, **rule-based logic** assigns a threat type from flow features:

| Pattern | Threat Type |
|---------|-------------|
| 1–6 packets, SYN flag or short duration | PortScan |
| TCP to ports 21, 22, 23, 3389, 445, 2–300 packets | Brute Force |
| flow_pkts_s > 1500 or flow_bytes_s > 1e6 | DDoS |
| >500 packets in <15 seconds | DDoS |
| >5MB in <60 seconds | DDoS |
| TCP to 80/443, >20KB, 4+ packets | Web Attack |
| TCP to 443, 2–25 packets, avg 50–300 bytes | Heartbleed |
| flow_pkts_s > 200, 8+ packets | Bot |
| UDP, >20 packets, anomaly_score > 0.4 | Bot |
| Non-standard port, 4+ packets, >500 bytes | Infiltration |
| anomaly_score > 0.8 | DDoS |
| anomaly_score > 0.6 | Bot |
| anomaly_score > 0.45 | Bot |
| 1–8 packets | PortScan |
| (fallback) | Anomaly |

---

## 5. Flow Features (79 total)

The model expects **79 CIC-style features** per flow, including:

- **Basic:** `src_port`, `dst_port`, `protocol`, `flow_duration`, `flow_byts_s`, `flow_pkts_s`
- **Packet counts:** `tot_fwd_pkts`, `tot_bwd_pkts`, `fwd_pkts_s`, `bwd_pkts_s`
- **Byte stats:** `totlen_fwd_pkts`, `totlen_bwd_pkts`
- **Packet lengths:** `fwd_pkt_len_max/min/mean/std`, `bwd_pkt_len_*`, `pkt_len_*`
- **Inter-arrival times:** `flow_iat_*`, `fwd_iat_*`, `bwd_iat_*`
- **TCP flags:** `syn_flag_cnt`, `fin_flag_cnt`, `rst_flag_cnt`, `psh_flag_cnt`, etc.
- **Other:** `down_up_ratio`, `init_fwd_win_byts`, `init_bwd_win_byts`, `subflow_*`, etc.

Missing features are filled with 0 before scoring.

---

## 6. Active Monitoring

### 6.1 What It Is

Live packet capture on a chosen network interface. Packets are turned into flows, classified, and stored in the same database with `monitor_type = 'active'`.

### 6.2 How It Works

1. **Start:** User selects interface (e.g. `lo`, `enp0s31f6`) and clicks Start.
2. **Capture:** Scapy `sniff()` runs every **5 seconds** on the interface.
3. **Flow building:** Packets are grouped by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) and 79 features are computed.
4. **Classification:** Same pipeline as passive: IF anomaly detection → threat inference → risk scoring.
5. **Storage:** Flows are inserted into `flows` with `monitor_type = 'active'`.

### 6.3 Requirements

- Backend must run with **sudo** for raw packet capture
- Scapy installed
- Default interface `lo` captures local API traffic for easy testing

### 6.4 Data Flow

```
Interface (lo/eth0/etc) → Scapy sniff(5s) → build_flows_from_packets()
  → decision_engine.classify_flows() → db.insert_flows(monitor_type="active")
```

### 6.5 Where to See It

- **Dashboard** → Active toggle
- **Traffic Analysis** → Active toggle
- **Anomalies** → Active toggle
- **History** → Active toggle (if active sessions are stored)

---

## 7. Passive Monitoring

### 7.1 What It Is

Analysis of **uploaded files** (CSV or PCAP). No live capture; data comes from historical or exported captures.

### 7.2 How It Works

1. **Upload:** User uploads a CSV or PCAP file.
2. **Conversion:** PCAP/PCAPNG is converted to CSV via CICFlowMeter (if needed).
3. **Chunked processing:** CSV is read in chunks (e.g. 50,000 rows).
4. **Classification:** Same pipeline: features → IF + RF (if present) → threat inference → risk scoring.
5. **Storage:** Flows are inserted with `monitor_type = 'passive'` and linked to an `analysis_id`.
6. **History:** An entry is created in `analysis_history` for the upload.

### 7.3 Data Flow

```
Upload (CSV/PCAP) → [PCAP→CSV if needed] → read chunks → clean_data()
  → decision_engine (IF + RF) → db.insert_flows(monitor_type="passive")
  → db.insert_analysis_history()
```

### 7.4 Where to See It

- **Dashboard** → Passive toggle
- **Traffic Analysis** → Passive toggle
- **Anomalies** → Passive toggle
- **History** → Passive toggle (upload analyses)
- **Upload** page → Analysis results

---

## 8. Active vs Passive Comparison

| Aspect | Active | Passive |
|--------|--------|---------|
| **Data source** | Live packets on interface | Uploaded CSV/PCAP |
| **When** | Real-time, continuous | One-time per upload |
| **Interface** | User selects (lo, eth0, etc.) | N/A |
| **Backend** | Must run with sudo | No special privileges |
| **monitor_type** | `active` | `passive` |
| **analysis_id** | `None` | UUID of the upload |
| **History** | No analysis entries (by default) | One entry per upload |
| **Use case** | Live network monitoring | Offline analysis of captures |

---

## 9. Quick Reference

### Anomaly Decision

- **Isolation Forest** `predict() == -1` → anomaly
- **Contamination** ≈ 1% of flows treated as anomalous
- **No explicit score threshold**; model uses internal ranking

### Risk Levels

- **Critical:** > 80%
- **High:** > 60%
- **Medium:** > 30%
- **Low:** ≤ 30%

### Model Files

- `training_pipeline/models/unsupervised/if_model.pkl` — Isolation Forest
- `training_pipeline/models/supervised/rf_model.pkl` — Random Forest (optional)
- `training_pipeline/models/artifacts/scaler.pkl` — Feature scaler
- `training_pipeline/models/artifacts/feature_names.pkl` — 79 feature names

---

## 10. Active Analysis: End-to-End Flow

1. **User** starts Active Monitoring and selects an interface (e.g. `lo`, `enp0s31f6`).
2. **Backend** starts a background thread that runs every **5 seconds**:
   - **Capture:** `scapy.sniff(iface=interface, timeout=5, count=50000)` on that interface.
   - **Build flows:** Packets are grouped by (src_ip, dst_ip, src_port, dst_port, protocol); 79 features are computed per flow.
   - **Classify:** Same pipeline as passive: scale features → IF predict/decision_function → if anomaly, infer threat type from rules → compute risk.
   - **Insert:** Flows are written to the DB with `monitor_type = 'active'`.
3. **Dashboard / Traffic / Anomalies** read from the same DB; the "Active" toggle filters by `monitor_type = 'active'`.

No separate "active analysis" process — it’s the same classification pipeline fed by live capture instead of an uploaded file.

---

## 11. Criteria & Threshold Values (Reference)

### 11.1 Anomaly decision (Isolation Forest)

| Item | Value | Meaning |
|------|--------|--------|
| Contamination | 0.01 | ~1% of flows treated as anomalous |
| Anomaly flag | `predict(X) == -1` | Binary: flow is anomaly or not |
| Score transform | `0.5 - decision_function(X)`, clip to [0,1] | Display anomaly_score |

### 11.2 Risk level (risk_score in [0, 1])

| Level | Threshold |
|-------|-----------|
| Critical | risk > 0.8 |
| High | risk > 0.6 |
| Medium | risk > 0.3 |
| Low | risk ≤ 0.3 |

### 11.3 Threat-type rules (when flow is anomalous)

| Threat | Criteria |
|--------|----------|
| PortScan | 1 ≤ tot_pkts ≤ 6 and (syn_cnt ≥ 1 or duration < 3 s) |
| Brute Force | TCP, dst_port ∈ {21,22,23,3389,445}, 2–300 pkts, duration < 180 s |
| DDoS | flow_pkts_s > 1500 **or** flow_bytes_s > 1e6 **or** tot_pkts > 500 in <15 s **or** total_bytes > 5e6 in <60 s **or** anomaly_score > 0.85 and (flow_pkts_s > 200 or tot_pkts > 100) |
| Web Attack | dst_port ∈ {80,443}, TCP, total_bytes > 20000, tot_pkts ≥ 4 |
| Heartbleed | dst_port 443, 2–25 pkts, 50 ≤ avg_pkt_len ≤ 300 |
| Bot | flow_pkts_s > 200 and tot_pkts ≥ 8 **or** UDP and tot_pkts > 20 and anomaly_score > 0.4 **or** anomaly_score > 0.65 and tot_pkts ≥ 15 |
| Infiltration | dst_port not in {21,22,23,80,443,3389,445}, tot_pkts ≥ 4, total_bytes > 500 |
| (Score fallback) | anomaly_score > 0.8 → DDoS; > 0.6 → Bot; > 0.45 → Bot; 1–8 pkts → PortScan; else Anomaly |

### 11.4 Capture settings

| Setting | Value |
|--------|--------|
| Window duration | 5 seconds |
| Max packets per window | 50,000 |
| Default interface if none selected | `lo` |

---

## 12. On Which Network It Works

Active monitoring does **not** target “a network” by name or VLAN. It runs on **whatever interface you choose** on the machine where the backend runs:

- **`lo`** — Loopback. Traffic to/from the same machine (e.g. browser ↔ backend on that server). Good for testing.
- **`eth0` / `enp0s31f6` / etc.** — Physical or virtual NIC. All traffic seen by that interface (the segment that NIC is attached to) is captured.

So:

- On your laptop: you see traffic on the interface you select (e.g. Wi‑Fi or Ethernet).
- On a server in the NAL server room: you see traffic on the interface you select on **that server** (e.g. the NIC connected to the server-room network). No config change is required for “which network” — you just pick the right interface in the UI (list comes from Scapy `get_if_list()` on that host).

---

## 13. Running on Another Server (e.g. NAL Server Room)

You do **not** need to change backend or frontend **code** to run on a different server. You only need **configuration** so that the frontend can reach the backend and (optionally) so the backend listens on the right address.

### 13.1 Backend on the other server

- Copy/deploy the NAL app (backend + frontend build, or run frontend in dev) on that machine.
- Run the backend with **sudo** (required for packet capture), e.g.:
  ```bash
  cd nal/backend && sudo .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
  ```
- `--host 0.0.0.0` makes the API reachable from other hosts (e.g. your laptop or another VM). Port `8000` is the default; you can change it if needed.

### 13.2 Frontend reaching the backend

The frontend calls the API using **one base URL**. That URL is set by:

- **Build-time:** `VITE_API_URL` when you run `npm run build`.
- **Default if unset:** `http://localhost:8000/api` (only works when the browser and backend are on the same host).

So:

- **Option A — Backend on same host as frontend (e.g. both on the NAL server):**  
  - Serve the frontend (e.g. `npm run build` then serve `dist/`, or `npm run dev`).  
  - If you use the default and open the UI on that server (e.g. `http://server-ip:5173`), the browser will call `localhost:8000` **from the user’s machine**. That only works if the user is on the server itself (e.g. VNC/RDP to the server).  
  - If users open the UI from their laptop, set `VITE_API_URL` to the **backend’s URL** (e.g. `http://NAL-SERVER-IP:8000/api`), then rebuild the frontend.

- **Option B — Backend on NAL server, frontend on your laptop (or vice versa):**  
  - Set `VITE_API_URL=http://NAL-SERVER-IP:8000/api` (replace `NAL-SERVER-IP` with the server’s IP or hostname).  
  - Run `npm run build` in the frontend; serve the built files or run `npm run dev` (dev proxy can point to the same URL).  
  - No backend or frontend **code** changes — only this env var and rebuild.

### 13.3 Summary: what you actually change

| What | Change |
|------|--------|
| Backend code | None |
| Frontend code | None |
| Backend run | Same command, on the new server, with `--host 0.0.0.0` if accessed from other hosts |
| Frontend API URL | Set `VITE_API_URL` to `http://<backend-host>:8000/api` and rebuild (or run dev with that env) |
| Active monitoring interface | Choose the correct interface on the NAL server in the UI (e.g. the NIC facing the network you want to monitor) |
| Firewall | Allow port 8000 (and 5173 if you serve frontend on the server) as needed |

So: **no backend/frontend code edits**; only deploy, config (API URL), and choosing the right interface for active monitoring.
