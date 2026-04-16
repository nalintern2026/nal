# API, Database, and Execution Flow

## API Security and Envelope Behavior

## Security

- Protected `/api/*` endpoints require `x-api-key` header.
- Unprotected endpoints:
  - `GET /api/health`
  - `GET /api/model/integrity`
  - `GET /api/integrity`

## Response Envelope

Most API endpoints return standardized envelope:

- success: `{status, data, error: null, timestamp}`
- failed/degraded: `{status, data, error:{code,message}, timestamp}`

Some utility endpoints return raw JSON structures (not wrapped), notably classification and SBOM payload endpoints.

## API Surface (Implemented Routes)

## Upload APIs

- `POST /api/upload`
- `GET /api/upload/jobs`
- `GET /api/upload/jobs/{job_id}`
- `GET /api/upload/{analysis_id}/flows`

## Realtime APIs

- `POST /api/realtime/start`
- `POST /api/realtime/stop`
- `GET /api/realtime/status`
- `GET /api/realtime/interfaces`

## Alerts APIs

- `GET /api/alerts`
- `GET /api/alerts/{alert_id}`
- `PATCH /api/alerts/{alert_id}`

## Cases APIs

- `POST /api/cases`
- `GET /api/cases`
- `GET /api/cases/{case_id}`
- `POST /api/cases/{case_id}/alerts`
- `PATCH /api/cases/{case_id}`

## Model APIs

- `GET /api/models/metrics`
- `GET /api/model/integrity`
- `GET /api/model/versions`
- `GET /api/model/active`

## Integrity/Health APIs

- `GET /api/health`
- `GET /api/integrity`
- `GET /api/threat-feeds/status`

## Other Operational APIs

- dashboard/traffic/anomaly/history:
  - `GET /api/dashboard/stats`
  - `GET /api/traffic/flows`
  - `GET /api/traffic/trends`
  - `GET /api/anomalies`
  - `GET /api/history`
  - `GET /api/history/{analysis_id}`
- OSINT page:
  - `GET /api/osint/flows`
- SBOM/security:
  - `POST /api/security/sbom/analyze`
  - `GET /api/security/sbom`
  - `GET /api/security/vulnerabilities`
  - `GET /api/security/sbom/download`

## Database Schema (Operational View)

## `flows.db` Main Tables

- **`flows`**: per-flow persisted output  
  includes traffic fields, ML output, threat/CVE fields, OSINT/feed fields, explanation, monitor type, model version.
- **`upload_jobs`**: async upload tracking (`QUEUED/PROCESSING/COMPLETED/FAILED`) + summary payload.
- **`analysis_history`**: session-level metadata for passive uploads and active runs.
- **`alerts`**: alert rows with correlation and lifecycle fields (`status`, `priority`, `occurrence_count`, `last_seen`, etc.).
- **`cases`**: incident/case objects (`title`, `description`, `status`, `created_at`).
- **`case_alerts`**: many-to-many link between cases and alerts.
- **`model_versions`**: version records and active flag.

## `passive_timeline.db`

- **`passive_upload_points`**: compact passive timeline points for dashboard rendering.

## Queue System

## Preferred path

- `queue_service.py` enqueues flow batches to Redis and runs Redis consumer worker with retry.

## Fallback path

- If Redis is unavailable, enqueue uses `flow_queue.py` in-process queue worker.

Both paths converge on `db.insert_flows(...)`.

## Retention and Cleanup

Retention cleanup executes:

- on backend startup,
- periodically (hourly loop).

Cleanup removes:

- old `flows`,
- old `upload_jobs`,
- old resolved alerts.

Retention horizon is controlled by `DATA_RETENTION_DAYS`.

## End-to-End Execution Lifecycle

## Passive Upload Lifecycle

1. User uploads file.
2. Upload job created and background processing starts.
3. Data is chunk-read and classified.
4. Enrichment adds OSINT/feed/CVE/explanation fields.
5. Flow batches are queued and inserted.
6. Analysis summary + history are persisted.
7. Frontend fetches job/flows and displays results.

## Active Monitoring Lifecycle

1. Realtime monitor starts packet capture.
2. Packets are transformed into flow windows.
3. Inference + enrichment run on each batch.
4. Batches are enqueued and stored with `monitor_type=active`.
5. Session summary is written to history on stop.
6. Dashboard/anomaly/history pages render active data.

## Alert/Case Lifecycle

1. Risk/final-score thresholds trigger alert creation.
2. Correlation logic may merge into existing alert and increment occurrence count.
3. UI can filter and resolve alerts.
4. Cases can be created and linked to alerts for investigation tracking.
