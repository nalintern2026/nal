# Module Breakdown

## Backend API Module (`nal/backend/app/main.py`)

- **Purpose:** Central HTTP interface and orchestration layer.
- **Key Inputs:** file uploads, query parameters, realtime control commands, SBOM files.
- **Key Outputs:** JSON responses for UI/n8n; persistent DB writes via `db.py`.
- **Dependencies:** FastAPI, `decision_service`, `realtime_service`, `sbom_service`, `osint_routes`, `threat_feeds`, `db.py`.
- **Internal Working:** initializes DB at startup, defines all routes, validates uploads, and maps each route to service/database operations.

### Main API route groups

- **Health and metadata:** `/api/health`, `/api/classification/criteria`
- **Traffic analytics:** `/api/dashboard/stats`, `/api/traffic/flows`, `/api/traffic/trends`, `/api/anomalies`
- **Upload and history:** `/api/upload`, `/api/upload/{analysis_id}/flows`, `/api/history`, `/api/history/{analysis_id}`
- **Realtime controls:** `/api/realtime/start`, `/api/realtime/stop`, `/api/realtime/status`, `/api/realtime/interfaces`
- **Threat intelligence:** `/api/threat-feeds/status`, `/api/osint/flows`
- **Model telemetry:** `/api/models/metrics`
- **SBOM security:** `/api/security/sbom/analyze`, `/api/security/sbom`, `/api/security/vulnerabilities`, `/api/security/sbom/download`

## Database Module (`nal/backend/app/db.py`)

- **Purpose:** Persistent storage and aggregated querying over flow/security telemetry.
- **Key Files:** `flows.db` and `passive_timeline.db` (root), schema logic in `init_db()` / `init_passive_timeline_db()`.
- **Inputs:** enriched flow dictionaries from passive/active processing.
- **Outputs:** paginated rows, dashboard aggregates, trend points, analysis reports.
- **Dependencies:** `sqlite3`, thread lock for safe concurrent access.

### Data schema responsibility

- `flows` table stores per-flow network and ML fields:
  - network: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, timing and packet/byte stats
  - ML/security: `classification`, `threat_type`, `cve_refs`, `classification_reason`, `confidence`, `anomaly_score`, `risk_score`, `risk_level`, `is_anomaly`
  - source marker: `monitor_type` (`passive` or `active`)
- `analysis_history` stores summarized upload-analysis reports and JSON distributions.
- `passive_upload_points` in `passive_timeline.db` stores passive timeline chart points.

## Decision Module (`nal/backend/app/services/decision_service.py`)

- **Purpose:** ML inference pipeline for uploaded files and realtime flow batches.
- **Inputs:** CSV rows or raw flow feature dicts.
- **Outputs:** per-flow `classification`, `confidence`, `anomaly_score`, `risk_score`, `risk_level`, `threat_type`, `cve_refs`.
- **Dependencies:** model artifacts from `training_pipeline/models`, `core.feature_engineering`, `classification_config`.
- **Internal Working:** loads artifacts once, optionally converts PCAP to CSV, processes in chunks, computes hybrid scoring, and returns report structures.

### Actual prediction sequence (passive path)

1. **Load and normalize input** (CSV direct, or PCAP->CSV with `cicflowmeter`).
2. **Chunk loop** (`pandas.read_csv(..., chunksize=50000)`).
3. **Feature cleaning** via `clean_data()` and column strip.
4. **Feature alignment** to `feature_names.pkl` (missing columns set to 0).
5. **Scale** using persisted `scaler.pkl`.
6. **Supervised prediction**:
   - if RF + label encoder exist: `predict()` + `predict_proba()`
   - else fallback label `BENIGN`, confidence `0.5`
7. **Unsupervised prediction**:
   - `if_model.predict()` for anomaly flag
   - `decision_function()` transformed to clipped `anomaly_score` in `[0,1]`
8. **Override logic**:
   - if `is_anomaly` and RF says `BENIGN`, call `infer_anomaly_threat_type(...)`
9. **Risk logic**:
   - benign/anomaly branch vs threat branch with configured formulas
10. **Explainability enrichment**:
    - map threat->CVE refs and build `classification_reason`
11. **Write rows** via `on_chunk_processed` callback into DB.

## Realtime Monitoring Module (`nal/backend/app/services/realtime_service.py`)

- **Purpose:** Active packet capture and near-real-time flow inference.
- **Inputs:** network packets from selected interface using Scapy.
- **Outputs:** active-mode flow records inserted to DB.
- **Dependencies:** Scapy, `decision_service.classify_flows`, `db.insert_flows`.
- **Internal Working:** capture loop (5s windows), packet grouping by normalized 5-tuple, CIC-like feature aggregation, classification, DB insertion.

### Packet capture and flow build internals

- Capture uses `sniff(iface=<selected or lo>, timeout=5, count=50000)`.
- Handles interface fallback (`iface=None`) if selected NIC is unavailable.
- Groups packets into bidirectional normalized flows:
  - key uses endpoint tuple ordering, so forward and reverse packets become one flow.
- For each flow it computes CIC-like features:
  - packet length stats, rates, total bytes/packets,
  - IAT stats,
  - TCP flag counters (`SYN`, `ACK`, `RST`, etc.),
  - header/window/subflow metrics.
- Resulting feature dict is passed to `decision_engine.classify_flows()` (same model path as upload mode).
- Persisted rows are forced to `monitor_type='active'`, `upload_filename='realtime'`.

## Classification Rules Module (`nal/backend/app/classification_config.py`)

- **Purpose:** Rule and threshold authority for risk mapping and threat/CVE semantics.
- **Inputs:** flow-derived risk score, anomaly score, feature behavior.
- **Outputs:** risk levels, inferred unsupervised threat labels, explanatory strings.
- **Dependencies:** consumed primarily by `decision_service`.

### Threshold and mapping content

- Risk thresholds:
  - `Critical > 0.8`, `High > 0.6`, `Medium > 0.3`, else `Low`
- Anomaly fallback thresholds:
  - score-based fallback for `DDoS`, `Bot`, `Anomaly`
- Threat rules include ports/rates/flags heuristics for:
  - `PortScan`, `Brute Force`, `DDoS`, `Web Attack`, `Heartbleed`, `Bot`, `Infiltration`
- Threat-CVE mapping table used to annotate responses with representative CVE references.

## SBOM Security Module (`nal/backend/app/services/sbom_service.py`)

- **Purpose:** Dependency file parsing, CycloneDX generation, OSV vulnerability lookup.
- **Inputs:** uploaded manifests (`requirements.txt`, `package.json`, lock files, etc.).
- **Outputs:** components list, vulnerabilities, severity distribution, remediation tips.
- **Dependencies:** `cyclonedx-python-lib` (if available), `requests` (OSV API), regex/json parsers.

## OSINT Module (`nal/backend/app/services/osint.py`, `nal/backend/app/osint_routes.py`)

- **Purpose:** enrich anomaly flows with AbuseIPDB/VirusTotal signals and expose OSINT-filtered APIs.
- **Inputs:** candidate public IP from anomalous flow context.
- **Outputs:** `abuse_score`, `vt_score`, `final_score`, `final_verdict`, provider status fields per flow.
- **Dependencies:** outbound HTTP to AbuseIPDB and VirusTotal, DB enrichment fields, `/api/osint/flows`.

## Threat Feed Module (`nal/backend/app/services/threat_feeds.py`)

- **Purpose:** maintain local threat-feed state in background and expose status endpoint.
- **Inputs:** configured feed sources and refresh schedule.
- **Outputs:** feed health/status payload from `/api/threat-feeds/status`.
- **Dependencies:** background daemon refresh started in `main.py`.

## Shared Feature Engineering Module (`nal/core/feature_engineering.py`)

- **Purpose:** data cleaning and preprocessing for training/inference consistency.
- **Inputs:** raw flow DataFrame.
- **Outputs:** scaled numeric matrix, optional encoded labels, scaler/encoder artifacts.
- **Dependencies:** NumPy, Pandas, scikit-learn preprocessing.

## Training Orchestration Module (`nal/training_pipeline/train.py`)

- **Purpose:** Train supervised and unsupervised models, save artifacts/metrics.
- **Inputs:** CSV files under processed flow datasets (recursive).
- **Outputs:** `rf_model.pkl`, `if_model.pkl`, scaler/encoder/features, `metrics.json`.
- **Dependencies:** `core.feature_engineering`, scikit-learn estimators.

### Model training specifics

- Supervised model: `RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)`.
- Unsupervised model: `IsolationForest(n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1)`.
- Isolation Forest is trained on BENIGN rows when BENIGN label is available.
- `metrics.json` stores `training_info`; per-model metrics are written when supervised training is executed successfully.

## Training Support Scripts (`nal/training_pipeline/scripts`)

- `generate_synthetic_data.py`: fallback synthetic CIC-like dataset generation.
- `generate_doomsday_flows.py`: synthetic processed-flow generator with attack/severity variation.
- `pcap_chunks_to_flows.py`: batch conversion from pcap chunks to CSV via CICFlowMeter.
- `setup_project.py`: legacy setup helper referencing path config module (currently not aligned with present tree).

## Frontend Module (`nal/frontend/src`)

- **Purpose:** visualization and operator control plane.
- **Key Files:** `App.jsx`, `services/api.js`, page components.
- **Inputs:** backend APIs and user interaction.
- **Outputs:** dashboards, triage tables, report views, monitor controls, SBOM UI.
- **Dependencies:** React, Axios, Chart.js, react-router, Tailwind.

## Automation Module (`nal/n8n`)

- **Purpose:** no-code orchestration for periodic checks, alerts, reports, and control hooks.
- **Key Files:** five workflow JSON definitions + `import_workflows.sh`.
- **Inputs:** scheduled triggers/webhooks + backend API responses.
- **Outputs:** webhook/Slack notifications, monitor/start-stop actions, report payloads.
