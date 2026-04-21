````md
# Architecture and Dataflow

## System Architecture (Diagram)

```mermaid
flowchart TD
    A[React Frontend - Pages & API Layer]
    B[FastAPI Backend - Main App]

    A --> B

    B --> C[Decision Service (RF + IF)]
    B --> D[Realtime Service (Packets → Flows)]
    B --> E[OSINT & Integrity Services]

    C --> F[Queue Service]
    D --> F
    E --> F

    F --> G[Redis Queue]
    F --> H[In-Process Queue]

    G --> I[Database Layer]
    H --> I
````

---

## Backend Structure (FastAPI Services)

Main orchestration is in:

`backend/app/main.py`

Core backend responsibilities:

* **decision_service.py**
  Inference, scoring, enrichment, alert triggering

* **realtime_service.py**
  Packet capture and active flow generation

* **queue_service.py**
  Redis queue + fallback enqueue path

* **flow_queue.py**
  In-process queue worker fallback

* **db.py**
  Schema initialization, query helpers, persistence APIs

* **osint.py**
  AbuseIPDB / VirusTotal + feed-aware score fusion

* **threat_feeds.py**
  Periodic local feed refresh + matching

* **sbom_service.py**
  Dependency parsing + OSV vulnerability lookup

* **integrity_service.py & model_integrity.py**
  Runtime integrity checks

---

## Frontend Structure (React + API Layer)

* **Router & Layout**

  * `frontend/src/App.jsx`
  * `components/Layout.jsx`

* **API Abstraction**

  * `frontend/src/services/api.js`

### Page Modules

* Dashboard
* Upload
* History
* TrafficAnalysis
* Anomalies
* OSINTValidation
* ModelPerformance
* ActiveMonitoring
* IntegrityDashboard
* Alerts
* Cases
* SBOMSecurity

📌 The frontend relies on backend envelope-style responses and uses
`friendlyMessage` for normalized error handling.

---

## Database Design Overview

### Main Operational DB (`flows.db`)

* **flows**
  Enriched per-flow records (ML + OSINT + CVE + explanation + monitor type)

* **upload_jobs**
  Async upload state and result summary

* **analysis_history**
  Metadata for passive and active sessions

* **alerts**
  Correlated alerts with:

  * status
  * priority
  * occurrence count
  * lifecycle fields

* **cases**
  Incident/case records (title, description, status)

* **case_alerts**
  Mapping between cases and alerts

* **model_versions**
  Model version lifecycle state

---

### Secondary DB (`passive_timeline.db`)

* **passive_upload_points**
  Timeline points for dashboard visualization

---

## Ingestion Pipelines

### Passive Upload Flow

1. `POST /api/upload` streams file to temporary storage
2. Upload job created with **QUEUED** status
3. Background processing reads file in chunks
4. Flow batches enqueued (`monitor_type = passive`)
5. Summary + analysis history stored
6. Job status → **COMPLETED / FAILED**
7. Frontend retrieves via polling or direct response

---

### Active Realtime Flow

1. `POST /api/realtime/start` → starts packet capture
2. Packets converted into flow-based feature records
3. Flow batches classified & enriched (`monitor_type = active`)
4. `POST /api/realtime/stop` → stops capture
5. Session summary stored
6. Dashboard + history updated

---

## Queue-Based Processing

* **Preferred:** Redis queue (`netguard:flow_batches`) with retry mechanism
* **Fallback:** In-process queue (`queue.Queue(maxsize=200)`)

Both pipelines insert into:

`db.insert_flows(...)`

📌 Queue health is exposed via system integrity endpoints

---

## Decision Pipeline Dataflow

```
Packets / CSV / PCAP
    → Feature Extraction & Normalization
    → Random Forest Classification + Confidence
    → Isolation Forest Anomaly Scoring
    → Threat Type & CVE Mapping
    → OSINT + Threat Feed Enrichment (for anomalies)
    → Fused Final Score & Verdict
    → Risk Level & Explanation
    → Queue Enqueue
    → Database Persistence (SQLite)
    → Alert Correlation & Update
    → Frontend Visualization
```

```
```
