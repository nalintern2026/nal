# Architecture and Dataflow

## System Architecture (Text Diagram)

```text
 flowchart TD

    A[React Frontend<br/>(pages + api.js layer)]
    B[FastAPI Backend<br/>app/main.py]

    A -->|HTTP /api/*<br/>x-api-key| B

    B --> C[Decision Service<br/>RF + IF Inference]
    B --> D[Realtime Service<br/>Packet → Flows]
    B --> E[SBOM / Integrity / OSINT<br/>Threat Feeds & Checks]

    C --> F[Queue Service]
    D --> F
    E --> F

    F -->|Redis (optional)| G[(Redis Queue)]
    F -->|Fallback| H[(In-Process Queue)]

    G --> I[DB Layer<br/>flows.db + passive_timeline.db]
    H --> I
```

## Backend Structure (FastAPI Services)

Main orchestration is in `backend/app/main.py`. Core backend responsibilities are split as:

- `decision_service.py`: inference, scoring, enrichment, alert trigger.
- `realtime_service.py`: packet capture and active flow generation.
- `queue_service.py`: Redis queue + fallback enqueue path.
- `flow_queue.py`: in-process queue worker fallback.
- `db.py`: schema initialization, query helpers, persistence APIs.
- `osint.py`: AbuseIPDB/VT + feed-aware score fusion.
- `threat_feeds.py`: periodic local feed refresh + matching.
- `sbom_service.py`: dependency parsing + OSV vulnerability lookup.
- `integrity_service.py` and `model_integrity.py`: runtime integrity checks.

## Frontend Structure (React + API Layer)

- Router and layout shell: `frontend/src/App.jsx`, `components/Layout.jsx`.
- API abstraction: `frontend/src/services/api.js`.
- Page modules:
  - `Dashboard`, `Upload`, `History`, `TrafficAnalysis`, `Anomalies`
  - `OSINTValidation`, `ModelPerformance`, `ActiveMonitoring`
  - `IntegrityDashboard`, `Alerts`, `Cases`, `SBOMSecurity`

The frontend relies on backend envelope-style responses for most routes and uses `friendlyMessage` for normalized error display.

## Database Design Overview

Main operational DB (`flows.db`) includes:

- `flows`: enriched per-flow records (ML + OSINT + CVE + explanation + monitor type).
- `upload_jobs`: async upload state and result summary.
- `analysis_history`: metadata for passive and active sessions.
- `alerts`: correlated alerts with status/priority/correlation fields.
- `cases` and `case_alerts`: incident workflow and alert linkage.
- `model_versions`: model version lifecycle state.

Secondary DB (`passive_timeline.db`) includes:

- `passive_upload_points`: passive timeline points for dashboard rendering.

## Ingestion Pipelines

## Passive Upload Flow

1. `POST /api/upload` streams file to temp storage.
2. Upload job row is created with `QUEUED`.
3. Background task executes file analysis in chunks.
4. Chunk callback enqueues flow batches (`monitor_type=passive`).
5. Summary + history are persisted; job becomes `COMPLETED`/`FAILED`.
6. Upload UI polls job endpoint or handles direct-result mode.

## Active Realtime Flow

1. `POST /api/realtime/start` starts capture loop.
2. Packet windows are converted to flow-like feature rows.
3. Batches are classified/enriched and enqueued (`monitor_type=active`).
4. `POST /api/realtime/stop` ends loop and persists session summary.
5. Dashboard/history reflect active-session data.

## Queue-Based Processing

- Preferred backend: Redis list queue (`netguard:flow_batches`) with consumer retry.
- Fallback backend: daemon in-process `queue.Queue(maxsize=200)`.
- Insert target for both: `db.insert_flows(...)`.
- Queue status appears in health/integrity outputs.

## Decision Pipeline Dataflow

```text
Packets/CSV/PCAP
    -> feature extraction/normalization
    -> RF classification + confidence
    -> IF anomaly scoring
    -> threat-type + CVE mapping
    -> OSINT + threat-feed enrichment (for anomalies)
    -> fused final score + verdict
    -> risk level + explanation
    -> queue enqueue
    -> SQLite persistence
    -> alert correlation/update
    -> frontend visualization
```
