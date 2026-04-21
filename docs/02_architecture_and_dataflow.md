# Architecture and Dataflow

## System Architecture (Diagram)

```mermaid
flowchart TD

    A[React Frontend - pages and api layer]
    B[FastAPI Backend - main app]

    A -->|HTTP API with key| B

    B --> C[Decision Service - RF and IF inference]
    B --> D[Realtime Service - packet to flows]
    B --> E[OSINT and Integrity Services]

    C --> F[Queue Service]
    D --> F
    E --> F

    F -->|Redis optional| G[Redis Queue]
    F -->|Fallback| H[In Process Queue]

    G --> I[Database Layer - flows db and timeline db]
    H --> I
Backend Structure (FastAPI Services)

Main orchestration is in backend/app/main.py. Core backend responsibilities are split as:

decision_service.py: inference, scoring, enrichment, alert trigger.
realtime_service.py: packet capture and active flow generation.
queue_service.py: Redis queue + fallback enqueue path.
flow_queue.py: in-process queue worker fallback.
db.py: schema initialization, query helpers, persistence APIs.
osint.py: AbuseIPDB/VT + feed-aware score fusion.
threat_feeds.py: periodic local feed refresh + matching.
sbom_service.py: dependency parsing + OSV vulnerability lookup.
integrity_service.py and model_integrity.py: runtime integrity checks.
Frontend Structure (React + API Layer)
Router and layout shell: frontend/src/App.jsx, components/Layout.jsx.
API abstraction: frontend/src/services/api.js.
Page modules:
Dashboard
Upload
History
TrafficAnalysis
Anomalies
OSINTValidation
ModelPerformance
ActiveMonitoring
IntegrityDashboard
Alerts
Cases
SBOMSecurity

The frontend relies on backend envelope-style responses for most routes and uses friendlyMessage for normalized error display.

Database Design Overview

Main operational DB (flows.db) includes:

flows: enriched per-flow records (ML + OSINT + CVE + explanation + monitor type).
upload_jobs: async upload state and result summary.
analysis_history: metadata for passive and active sessions.
alerts: correlated alerts with status, priority, occurrence count, and lifecycle fields.
cases: incident/case records with title, description, and status.
case_alerts: mapping between cases and alerts.
model_versions: model version lifecycle state.

Secondary DB (passive_timeline.db) includes:

passive_upload_points: passive timeline points for dashboard rendering.
Ingestion Pipelines
Passive Upload Flow
POST /api/upload streams file to temporary storage.
Upload job is created with QUEUED status.
Background processing reads and analyzes file in chunks.
Flow batches are enqueued with monitor_type=passive.
Summary and analysis history are stored.
Job status becomes COMPLETED or FAILED.
Frontend retrieves results via polling or direct response.
Active Realtime Flow
POST /api/realtime/start starts packet capture.
Packets are converted into flow-based feature records.
Flow batches are classified and enriched (monitor_type=active).
POST /api/realtime/stop stops capture.
Session summary is stored.
Dashboard and history reflect active session data.
Queue-Based Processing
Preferred: Redis queue (netguard:flow_batches) with retry mechanism.
Fallback: in-process queue using queue.Queue(maxsize=200).
Both pipelines insert into: db.insert_flows(...).
Queue health is visible in system integrity endpoints.
Decision Pipeline Dataflow
Packets / CSV / PCAP
    -> feature extraction and normalization
    -> Random Forest classification + confidence
    -> Isolation Forest anomaly scoring
    -> threat type and CVE mapping
    -> OSINT + threat-feed enrichment (for anomalies)
    -> fused final score and verdict
    -> risk level and explanation
    -> queue enqueue
    -> database persistence (SQLite)
    -> alert correlation and update
    -> frontend visualization
