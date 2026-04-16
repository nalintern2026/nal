# NetGuard System Overview

## Project Definition

NetGuard is a FastAPI + React network security analysis platform that combines machine learning inference, threat-intelligence enrichment, and operational monitoring workflows. It supports two traffic-analysis modes:

- **Passive mode**: uploaded CSV/PCAP/PCAPNG files are analyzed in background jobs.
- **Active mode**: live packets are captured, converted to flow features, and analyzed continuously.

The platform is designed as a single-node deployment with SQLite persistence, API-key protection for most API routes, and a browser-based interface for analysts.

## What NetGuard Does

At runtime, NetGuard performs the following:

1. Ingests network flow data from upload or live capture.
2. Runs supervised + unsupervised ML inference per flow.
3. Derives risk score/risk level and threat semantics.
4. Enriches anomalous flows with OSINT and local threat-feed evidence.
5. Maps threat classes to CVE references where applicable.
6. Persists flows, summaries, jobs, alerts, and case links in SQLite.
7. Exposes API endpoints consumed by the React frontend.

## Dual-Mode Analysis

### Passive Analysis (Upload)

- User uploads a file to `POST /api/upload`.
- Backend validates extension/magic and file size.
- Job is queued in `upload_jobs` and processed asynchronously.
- File is analyzed chunk-by-chunk; flows are inserted through queue-backed writers.
- Result summary is stored and shown in Upload UI.

### Active Analysis (Realtime)

- User starts monitor via `POST /api/realtime/start`.
- Packet capture loop builds flow-like records from packet windows.
- Each batch is classified and enriched, then queued for DB insert.
- Session metadata is persisted into history when monitoring stops.

## High-Level Architecture

- **Backend**: FastAPI app with service modules for ML, OSINT, queueing, threat feeds, SBOM, integrity, and persistence.
- **Frontend**: React SPA with dedicated pages for dashboard, upload, anomalies, alerts, cases, integrity, and SBOM security.
- **Storage**:
  - `flows.db` for operational data.
  - `passive_timeline.db` for passive timeline points.
- **Queueing**:
  - Redis-backed queue if available.
  - Automatic fallback to in-process queue.

## Key Modules

### ML Engine

- Uses Random Forest (classification) and Isolation Forest (anomaly signal).
- Enforces strict artifact + feature compatibility before inference.
- Produces per-flow classification, anomaly score, confidence, risk score/level.

### OSINT System

- Applies to anomaly-flagged flows.
- Integrates AbuseIPDB, VirusTotal, and local feed matches.
- Uses rate limiting, retries, cache, and dedup controls.

### CVE Mapping

- Threat labels map to threat type + CVE references via static configuration.
- Classification reason text includes mapping context.

### SBOM Scanner

- Accepts user dependency files.
- Extracts components, queries OSV, computes severity distribution.
- Returns CycloneDX-formatted output when available.

### Alerting Engine

- Creates alerts on high/critical risk or high fused final score.
- Correlates similar alerts within a time window.
- Tracks occurrence count and last seen.

## Simplified Workflow (Narrative)

1. **Input arrives** from file upload or packet capture.
2. **Feature preparation** normalizes schema for model inference.
3. **ML inference** computes class, confidence, anomaly score.
4. **Threat semantics** attach threat type, CVE refs, and reason.
5. **OSINT/feed enrichment** augments anomaly flows and computes fused final score.
6. **Risk + verdict** fields are assigned and serialized into flow records.
7. **Queue pipeline** writes batches into SQLite.
8. **Alert logic** triggers correlated alerts when thresholds are met.
9. **Frontend APIs** display results, trends, alerts, and case workflows.
