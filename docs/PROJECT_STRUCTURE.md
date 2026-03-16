# NetGuard — Project Structure & Data Flow

Complete reference for the **Network Security Intelligence** system: structure, pages, API endpoints, data sources, and where everything is displayed.

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FRONTEND (React + Vite)                             │
│  nal/frontend/  │  Port: 5173 (dev)  │  API Base: VITE_API_URL or localhost:8000/api
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        │ HTTP (REST)
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           BACKEND (FastAPI)                                   │
│  nal/backend/   │  Port: 8000  │  /api/* endpoints
└─────────────────────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌──────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│  SQLite DB   │    │  Decision Engine │    │  SBOM Service        │
│  flows.db    │    │  (ML models)     │    │  (OSV API, CycloneDX) │
└──────────────┘    └──────────────────┘    └─────────────────────┘
```

---

## 2. Directory Structure

```
Network/
├── PROJECT_STRUCTURE.md          ← This file
├── THREAT_ANOMALY_DETECTION.md   ← Threat/anomaly spec
├── flows.db                      ← SQLite database (flows, analysis_history)
├── temp_uploads/                 ← Temp files during upload (process → discard)
│
└── nal/
    ├── frontend/                 ← React SPA
    │   ├── src/
    │   │   ├── App.jsx           ← Routes & layout
    │   │   ├── main.jsx          ← Entry point
    │   │   ├── components/
    │   │   │   └── Layout.jsx     ← Sidebar, nav, API status
    │   │   ├── pages/            ← All page components
    │   │   └── services/
    │   │       └── api.js        ← API client (axios)
    │   ├── index.html
    │   ├── vite.config.js
    │   └── package.json
    │
    ├── backend/
    │   └── app/
    │       ├── main.py           ← FastAPI app, all routes
    │       ├── db.py             ← SQLite CRUD, dashboard stats, flows, history
    │       ├── classification_config.py  ← Risk thresholds, CVE mapping
    │       └── services/
    │           ├── decision_service.py   ← ML analysis (RF + IF)
    │           └── sbom_service.py       ← SBOM parsing, OSV vuln check
    │
    ├── core/
    │   └── feature_engineering.py  ← Flow feature extraction
    │
    ├── training_pipeline/
    │   ├── train.py              ← Model training
    │   ├── models/
    │   │   └── metrics.json      ← Offline metrics (accuracy, precision, etc.)
    │   ├── preprocessing/
    │   ├── data_collection/
    │   └── scripts/
    │
    ├── security/
    │   └── sbom.json             ← Sample/static SBOM (optional)
    │
    ├── docs/
    ├── results/
    ├── SBOM_AUDIT.md
    ├── requirements.txt
    └── README.md
```

---

## 3. Frontend Pages & Routes

| Route | Page Component | Description |
|-------|----------------|-------------|
| `/` | `Dashboard` | Main overview: KPIs, attack distribution, timeline, risk, protocols, top IPs |
| `/upload` | `Upload` | Upload PCAP/PCAPNG/CSV → analyze → show results, flows, anomalies |
| `/history` | `History` | List of past analyses (from DB) |
| `/history/:id` | `HistoryReport` | Full report for one analysis |
| `/traffic` | `TrafficAnalysis` | Paginated flows, filters, trend charts |
| `/anomalies` | `Anomalies` | Threat-focused view: score distribution, attack breakdown, top threats |
| `/models` | `ModelPerformance` | ML metrics, confusion matrix, ROC AUC, live stats |
| `/active` | `ActiveMonitoring` | Live packet capture, start/stop, interface selector, status |
| `/security` | `SBOMSecurity` | SBOM upload, components, vulnerabilities, remediation |

---

## 4. API Endpoints & Data Flow

### 4.1 Health & Status

| Method | Endpoint | Data Source | Used By |
|--------|----------|-------------|---------|
| GET | `/api/health` | Backend state | `Layout` (API status indicator) |

---

### 4.2 Dashboard

| Method | Endpoint | Data Source | Used By |
|--------|----------|-------------|---------|
| GET | `/api/dashboard/stats` | `db.get_dashboard_stats()` → SQLite | `Dashboard` |

**Returns:** `total_flows`, `total_anomalies`, `anomaly_rate`, `avg_risk_score`, `attack_distribution`, `risk_distribution`, `timeline`, `protocols`, `top_sources`

**Displayed in Dashboard:**
- KPI cards: Total Flows, Anomalies, Avg Risk, Active Protocols
- Attack Distribution (doughnut)
- Traffic Timeline (line chart: total vs anomalies)
- Risk Distribution (bars + gauge)
- Protocol Distribution (bar chart)
- Top Source IPs table

---

### 4.3 Upload & Analysis

| Method | Endpoint | Data Source | Used By |
|--------|----------|-------------|---------|
| POST | `/api/upload` | `decision_engine.analyze_file()` → DB insert | `Upload` |
| GET | `/api/upload/{analysis_id}/flows` | `db.get_flows(analysis_id=...)` | `Upload`, `HistoryReport` |

**Upload flow:**
1. User selects PCAP/PCAPNG/CSV
2. Backend saves to `temp_uploads/`, runs `decision_engine.analyze_file()`
3. Flows inserted into `flows` table, metadata into `analysis_history`
4. Response: `id`, `total_flows`, `anomaly_count`, `avg_risk_score`, `attack_distribution`, `report_details`, `sample_flows`

**Displayed in Upload:**
- Result KPIs (Total Flows, Anomalies, Avg Risk, File Size)
- Protocol distribution, anomaly breakdown, risk breakdown
- Attack distribution (clickable → sample flows)
- All flows table (paginated via `getUploadFlows`)

---

### 4.4 History

| Method | Endpoint | Data Source | Used By |
|--------|----------|-------------|---------|
| GET | `/api/history` | `db.get_analysis_history()` | `History` |
| GET | `/api/history/{analysis_id}` | `db.get_history_report()` | `HistoryReport` |

**History list:** `analyses[]` with `analysis_id`, `filename`, `uploaded_at`, `file_size`, `total_flows`, `anomaly_count`, `avg_risk_score`, `monitor_type`

**History report:** Full metadata + `flows` (paginated) + `report_details` (protocol_distribution, risk_breakdown, anomaly_breakdown, attack_flow_samples)

**Displayed:**
- **History:** Cards with filename, date, size, flows, anomalies, risk; click → `/history/:id`
- **HistoryReport:** Same structure as Upload results; Attack Distribution, Risk Breakdown, Top Anomalies, Top Risk Flows, All Flows (paginated)

---

### 4.5 Traffic Analysis

| Method | Endpoint | Data Source | Used By |
|--------|----------|-------------|---------|
| GET | `/api/traffic/flows` | `db.get_flows()` with filters | `TrafficAnalysis` |
| GET | `/api/traffic/trends` | `db.get_traffic_trends()` | `TrafficAnalysis` |

**Params:** `page`, `per_page`, `classification`, `risk_level`, `src_ip`, `protocol`

**Flows:** Paginated flow rows from DB  
**Trends:** Hourly aggregates (`points[]`: `hour`, `total_flows`, `threat_flows`, `benign_flows`, `avg_risk_score`, `avg_confidence`, `threat_rate`)

**Displayed:**
- Filters: Source IP, Classification, Risk Level, Protocol
- Flow Volume & Threat Mix (line chart)
- Avg Risk, Confidence, Threat Rate (line chart)
- Flows table (Time, Src/Dst IP, Port, Protocol, Duration, B/s, Classification, Anomaly, Risk)
- Pagination

---

### 4.6 Anomalies

| Method | Endpoint | Data Source | Used By |
|--------|----------|-------------|---------|
| GET | `/api/anomalies` | `db.get_threat_data()` | `Anomalies` |

**Params:** `page`, `per_page`, `classification`, `risk_level`, `src_ip`, `protocol`

**Returns:** `total_anomalies`, `score_distribution`, `attack_breakdown`, `top_anomalies[]`, `page`, `total_pages`

**Displayed:**
- KPIs: Total Anomalies, High Severity (≥0.8), Attack Types
- Anomaly Score Distribution (bar)
- Attack Type Breakdown (doughnut)
- Top Threats table (Src/Dst IP, Protocol, Classification, Threat Type, CVE, Anomaly Score, Confidence, Risk Level)
- Filters + pagination

---

### 4.7 Model Performance

| Method | Endpoint | Data Source | Used By |
|--------|----------|-------------|---------|
| GET | `/api/models/metrics` | `metrics.json` + `db.get_dashboard_stats()` + `db.get_flows()` | `ModelPerformance` |

**Data sources:**
- **Offline:** `training_pipeline/models/metrics.json` → `models`, `training_info`
- **Live:** `db.get_dashboard_stats()` + recent flows → `live_metrics`, `model_status`

**Returns:** `models`, `training_info`, `live_metrics`, `model_status`, `source`

**Displayed:**
- **If no training models:** Live KPIs (Total Flows, Anomaly Rate, Avg Risk, Avg Confidence), Traffic Health Split, Risk Distribution, Runtime Quality Metrics, Model Readiness (radar), Model Status
- **If training models exist:** Model selector, Accuracy/Precision/Recall/F1 cards, Confusion Matrix, Metrics Radar, ROC AUC, Training Info, Model Comparison bar

---

### 4.8 Active / Realtime Monitoring

| Method | Endpoint | Data Source | Used By |
|--------|----------|-------------|---------|
| POST | `/api/realtime/start` | `realtime_monitor.start(interface)` | `ActiveMonitoring` |
| POST | `/api/realtime/stop` | `realtime_monitor.stop()` | `ActiveMonitoring` |
| GET | `/api/realtime/status` | `realtime_monitor.get_status()` | `ActiveMonitoring` |
| GET | `/api/realtime/interfaces` | `psutil.net_if_addrs()` | `ActiveMonitoring` |

**Flow:** User selects interface → Start → background thread captures packets (5s windows) → builds flows → classifies via decision engine → inserts into DB with `monitor_type=active`. Dashboard aggregates all flows.

---

### 4.9 SBOM Security

| Method | Endpoint | Data Source | Used By |
|--------|----------|-------------|---------|
| POST | `/api/security/sbom/analyze` | `sbom_service.analyze_dependency_file()` | `SBOMSecurity` |
| GET | `/api/security/sbom` | In-memory `_user_sbom_result` | `SBOMSecurity` |
| GET | `/api/security/vulnerabilities` | In-memory `_user_sbom_result` | `SBOMSecurity` |
| GET | `/api/security/sbom/download` | In-memory `_user_sbom_result` (CycloneDX JSON) | `SBOMSecurity` (download link) |

**Analyze flow:**
1. User uploads dependency file (requirements.txt, package.json, package-lock.json, etc.)
2. Backend validates type + size (max 5 MB), writes to temp, parses, builds SBOM, queries OSV
3. File deleted after processing; result stored in `_user_sbom_result`
4. Response: `components`, `vulnerabilities`, `total_components`, `total_vulnerabilities`, `severity_distribution`, `warnings`, etc.

**Displayed:**
- Upload zone (allowed: .txt, .json, Pipfile, poetry.lock, Gemfile, go.mod, Cargo.toml, etc.)
- KPIs: Components, Vulnerabilities, Critical/High, Scanner
- Tabs: Overview (doughnut + severity bars), Components (table: name, version, type, purl), Vulnerabilities (list with severity, fixed_in, tips, advisory link)
- SBOM Metadata, Download SBOM (CycloneDX JSON)
- Warnings (e.g. packages skipped for unknown version)

---

## 5. Database Schema (SQLite)

**File:** `flows.db` (project root)

### `flows` table
- `id`, `analysis_id`, `upload_filename`, `timestamp`
- `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`
- `duration`, `total_fwd_packets`, `total_bwd_packets`, `total_length_fwd`, `total_length_bwd`
- `flow_bytes_per_sec`, `flow_packets_per_sec`
- `classification`, `confidence`, `anomaly_score`, `risk_score`, `risk_level`
- `is_anomaly`, `threat_type`, `cve_refs`, `classification_reason`

### `analysis_history` table
- `analysis_id`, `filename`, `monitor_type`, `uploaded_at`, `file_size`
- `total_flows`, `anomaly_count`, `avg_risk_score`
- `attack_distribution`, `risk_distribution`, `report_details` (JSON)

---

## 6. Data Flow Summary

| Page | Primary API | Secondary API | Data Shown |
|------|-------------|---------------|------------|
| **Dashboard** | `GET /api/dashboard/stats` | — | KPIs, charts, top IPs |
| **Upload** | `POST /api/upload` | `GET /api/upload/:id/flows` | Analysis result, flows, anomalies |
| **History** | `GET /api/history` | — | Analysis list |
| **HistoryReport** | `GET /api/history/:id` | `GET /api/upload/:id/flows` | Report + flows |
| **TrafficAnalysis** | `GET /api/traffic/flows` | `GET /api/traffic/trends` | Flows table, trend charts |
| **Anomalies** | `GET /api/anomalies` | — | Threat stats, top anomalies |
| **ModelPerformance** | `GET /api/models/metrics` | — | Model metrics, live stats |
| **ActiveMonitoring** | `POST /api/realtime/start` | `GET /api/realtime/status`, `GET /api/realtime/interfaces` | Start/stop, status, interface list |
| **SBOMSecurity** | `POST /api/security/sbom/analyze` | `GET /api/security/sbom`, `GET /api/security/vulnerabilities` | SBOM, vulns, download |

---

## 7. Key Services

### Decision Engine (`decision_service.py`)
- Loads Random Forest (supervised) + Isolation Forest (unsupervised) + Scaler
- `analyze_file(path, file_type)` → parses PCAP/CSV, extracts features, classifies, assigns risk
- `classify_flows(flows_raw)` → classifies raw flow dicts (from packet capture) for realtime monitoring
- Output: flows with `classification`, `anomaly_score`, `risk_score`, `risk_level`, `threat_type`, `cve_refs`

### Realtime Monitor (`realtime_service.py`)
- `capture_packets(interface, duration)` → scapy sniff
- `build_flows_from_packets(packets)` → group by 5-tuple, compute stats
- `RealtimeMonitor` → background thread: capture → build → classify → insert (monitor_type=active)

### SBOM Service (`sbom_service.py`)
- Parses: requirements.txt, package.json, package-lock.json, yarn.lock, Pipfile, poetry.lock, Gemfile, Gemfile.lock, go.mod, Cargo.toml, Cargo.lock
- Builds CycloneDX BOM with purl
- Queries OSV API for vulnerabilities
- Returns components + vulnerabilities + severity + remediation tips

### Database (`db.py`)
- `get_dashboard_stats()` — aggregates from `flows` + `analysis_history`
- `get_flows()` — paginated, filterable
- `get_traffic_trends()` — hourly aggregates
- `get_threat_data()` — anomaly-focused with score/attack breakdown
- `get_analysis_history()`, `get_history_report()`
- `insert_flows()`, `insert_analysis()`

---

## 8. Environment & Run

- **Frontend:** `VITE_API_URL` (default `http://localhost:8000/api`)
- **Backend:** `uvicorn app.main:app` from `nal/backend/`
- **DB:** `flows.db` in project root (created automatically)
- **Temp uploads:** `temp_uploads/` (cleaned after each request)

---

*Last updated: March 2025*
