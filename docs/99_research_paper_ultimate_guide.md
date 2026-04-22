# NetGuard Research Paper Ultimate Guide

This document is a complete, paper-writing companion for the NetGuard project in `nal/`.  
It is designed to help you produce a high-quality academic report with accurate implementation-grounded claims.

---

## 1) Project Identity (Use in Title/Abstract/Intro)

**Project name:** NetGuard  
**Type:** AI-enabled network threat detection and validation platform  
**Core stack:** FastAPI backend + React frontend + SQLite + optional Redis  
**Core purpose:** Detect malicious/anomalous network behavior using hybrid ML and validate suspicious activity with threat intelligence.

**One-line definition:**  
NetGuard is a dual-mode (passive upload + active realtime capture) network security analysis system that combines Random Forest classification, Isolation Forest anomaly detection, and OSINT/local threat intelligence to generate risk-scored and explainable threat decisions.

---

## 2) What Is Actually Implemented (Evidence-Based Scope)

### 2.1 Fully Implemented Core Features

- Dual-mode ingestion:
  - Passive: `.csv`, `.pcap`, `.pcapng` upload analysis.
  - Active: realtime packet capture and continuous flow analysis.
- Hybrid ML inference:
  - Supervised model: Random Forest.
  - Unsupervised model: Isolation Forest.
- Risk scoring and risk level assignment (`Critical/High/Medium/Low`).
- Threat semantics:
  - Threat type labeling.
  - CVE reference mapping for known classes.
  - Classification rationale text.
- Intelligence enrichment:
  - External: AbuseIPDB + VirusTotal.
  - Internal: local downloadable threat-feed matching.
  - Fused final score and verdict tier.
- Asynchronous processing:
  - Redis-backed queue if available.
  - Automatic in-process queue fallback.
- Alerting and correlation:
  - Alert creation on threshold crossing.
  - Correlation window with occurrence count updates.
- Historical persistence:
  - Flow-level persistence.
  - Upload jobs and analysis history.
  - Active monitoring session history.
- Frontend analytics and operations pages:
  - Dashboard, upload, anomalies, alerts, history, active monitoring, model performance, OSINT validation, SBOM security.

### 2.2 Implemented Extensions Beyond Core Net Traffic Detection

- SBOM + dependency vulnerability scanning pipeline (OSV-backed).
- Integrity endpoints for model/runtime/database checks.
- Model version registration and active version tagging.

---

## 3) System Architecture (Chapter-Ready)

### 3.1 High-Level Components

1. **Presentation Layer (React)**  
   Analyst-facing dashboards and workflows for upload, monitoring, anomalies, alerts, and reports.

2. **API Orchestration Layer (FastAPI)**  
   Route handlers, authentication middleware, upload scheduling, realtime controls, and response normalization.

3. **Detection Layer (Decision Engine)**  
   Feature preparation, model inference, threat semantics, risk scoring, and enrichment triggering.

4. **Intelligence Layer**  
   OSINT APIs + local threat feeds + fusion scoring + verdict generation.

5. **Persistence and Queue Layer**  
   SQLite storage for operational records with queue-based batched inserts (Redis primary, in-process fallback).

### 3.2 Data Stores

- `flows.db` (main operational DB):
  - `flows`
  - `upload_jobs`
  - `analysis_history`
  - `alerts`
  - `cases`, `case_alerts`
  - `model_versions`
- `passive_timeline.db`:
  - passive dashboard timeline points.

### 3.3 Deployment Character

- Single-node architecture.
- Dockerized backend/frontend option available.
- API-key protection on most `/api/*` routes.

---

## 4) Methodology (Write This in Your Paper)

### 4.1 Research/Engineering Method

NetGuard follows a layered, end-to-end methodology:

1. **Traffic ingestion** from passive files and live packet capture.
2. **Flow normalization and schema alignment** to match trained artifact features.
3. **Dual-model detection** using supervised class inference and unsupervised anomaly scoring.
4. **Semantic threat interpretation** (threat type, CVE references, textual reason).
5. **Threat-intelligence validation** via local feeds and external OSINT.
6. **Score fusion and verdicting** to increase confidence and context.
7. **Alert generation and correlation** for operational triage.
8. **Persistence and dashboard analytics** for continuous analysis lifecycle.

### 4.2 Why Dual-Model Works Here

- Random Forest handles known/learned classes well.
- Isolation Forest captures outlier behavior for unknown or evolving threats.
- Override path enables anomaly-driven relabeling when RF predicts benign but IF flags abnormal behavior.

This allows NetGuard to handle both known attack categories and suspicious unknown patterns.

---

## 5) Core Algorithms and Formulas (Use in Technical Section)

### 5.1 Isolation Forest Anomaly Normalization

Runtime formula:

`anomaly_score = clip(0.5 - decision_function, 0, 1)`

Where:
- `decision_function` is IF output.
- `clip` bounds score to `[0, 1]`.

### 5.2 Risk Score Computation

Let:
- `conf` = RF confidence in `[0, 1]`
- `anom` = normalized anomaly score in `[0, 1]`

Risk logic:

- If label is benign:
  - `risk = anom * 0.6` (if anomaly flagged), else `0.0`
- If label is threat:
  - `risk = (conf * 0.7) + (anom * 0.3)`
- `risk` then clipped to `[0,1]`.

Risk levels:
- `Critical`: `risk > 0.8`
- `High`: `risk > 0.6`
- `Medium`: `risk > 0.3`
- `Low`: otherwise

### 5.3 OSINT/Feed Final Score Fusion

Let:
- `m` = ML anomaly confidence scaled to `[0,100]`
- `rf` = RF confidence scaled to `[0,100]`
- `f` = local feed score `[0,100]`
- `a` = AbuseIPDB score `[0,100]` (if available)
- `v` = VirusTotal score `[0,100]` (if available)

Branching formulas:

1. **API OSINT available**  
   `final = 0.30m + 0.20rf + 0.20f + 0.15a + 0.15v`

2. **Only feed evidence available**  
   `final = 0.35m + 0.25rf + 0.40f`

3. **No external intelligence available**  
   `final = 0.50m + 0.50rf`

Final score is bounded to `[0,100]`.

Verdict tiers:
- `>70`: Verified Threat
- `40..70`: Suspicious
- `20..40` or no OSINT data: Unconfirmed Threat
- `<20` with OSINT clean signal: Likely False Positive

---

## 6) Detailed Implementation Walkthrough

### 6.1 Passive Upload Pipeline

1. File upload endpoint receives traffic file.
2. Extension + magic-byte validation performed.
3. Upload job inserted as `QUEUED`.
4. Background task runs analysis:
   - PCAP/PCAPNG converted via `cicflowmeter`.
   - CSV read in chunks (large-file safe).
   - Features cleaned, validated, inferred.
5. Flow batches sent to queue service.
6. Queue worker persists records.
7. Summary and analysis history stored.
8. Job marked `COMPLETED` or `FAILED`.

### 6.2 Active Monitoring Pipeline

1. User starts monitor via API.
2. Scapy captures packet windows.
3. Packets grouped into flow-like feature rows.
4. Same decision pipeline classifies/enriches.
5. Active batches queued and written to DB.
6. On stop, session-level summary is persisted.

### 6.3 Threat Semantics

For each flow, NetGuard attaches:
- `classification`
- `threat_type`
- `cve_refs`
- `classification_reason`
- `risk_score`, `risk_level`
- OSINT fields where applicable (`abuse_score`, `vt_score`, `feed_score`, `final_score`, `final_verdict`, explanation payload).

---

## 7) API Surface You Can Mention

### 7.1 Operational APIs

- Health/integrity:
  - `/api/health`
  - `/api/model/integrity`
  - `/api/integrity`
- Dashboard and analytics:
  - `/api/dashboard/stats`
  - `/api/traffic/flows`
  - `/api/traffic/trends`
  - `/api/anomalies`
  - `/api/history`
- Upload lifecycle:
  - `/api/upload`
  - `/api/upload/jobs`
  - `/api/upload/{analysis_id}/flows`
- Realtime lifecycle:
  - `/api/realtime/start`
  - `/api/realtime/stop`
  - `/api/realtime/status`
  - `/api/realtime/interfaces`
- Intelligence:
  - `/api/osint/flows`
  - `/api/threat-feeds/status`
- Alert operations:
  - `/api/alerts`
  - `/api/alerts/{id}` (GET/PATCH)

### 7.2 Security APIs (Extension Scope)

- `/api/security/sbom/analyze`
- `/api/security/sbom`
- `/api/security/vulnerabilities`
- `/api/security/sbom/download`

---

## 8) Chapter-by-Chapter Paper Blueprint

### 8.1 Abstract (What to Include)

- Problem: traditional signature/rule-only IDS limitations.
- Proposal: hybrid ML + OSINT-validated framework.
- Key implemented capabilities: passive + active analysis, risk scoring, intelligence fusion.
- Practical outcome: explainable and operationally usable threat decisions.

### 8.2 Introduction

- Scale and complexity of modern traffic.
- Need for both known-attack classification and unknown-anomaly detection.
- Need for validation layer beyond raw ML outputs.
- NetGuard contribution statement (architecture + implementation + operationalization).

### 8.3 Literature Review

You can compare with:
- pure IDS signature systems,
- ML-only anomaly systems,
- threat-intelligence-only validation systems,
- DevSecOps pipeline security research (if you keep your current citations).

Position NetGuard as an integrated runtime detection-validation pipeline rather than an isolated model experiment.

### 8.4 Methodology

Use Section 4 and Section 5 from this guide almost directly.

### 8.5 System Design

Include:
- architecture block diagram,
- passive and active flow diagrams,
- database ER-style table relationship summary.

### 8.6 Implementation

Describe module decomposition:
- decision engine
- realtime service
- OSINT/feed service
- queueing
- persistence
- frontend dashboards.

### 8.7 Testing and Validation

Separate into:
- functional validation,
- performance and throughput,
- model-behavior validation,
- operational quality (alerts, correlation, false positive handling).

### 8.8 Results

Use measurable categories (see Section 9 templates).

### 8.9 Discussion

- strengths,
- known limitations,
- deployment constraints,
- practical use in SOC/lab environment.

### 8.10 Conclusion and Future Work

- summarize integrated value,
- propose adaptive thresholding, online learning, distributed storage, SIEM integration.

---

## 9) Ready-to-Use Result Templates

### 9.1 Functional Result Table (Template)

| Capability | Implemented | Validation Method | Status |
|---|---|---|---|
| CSV upload analysis | Yes | API + UI run | Pass |
| PCAP/PCAPNG analysis | Yes | conversion + inference check | Pass |
| Realtime active monitoring | Yes | capture start/stop + flow insert | Pass |
| RF + IF inference | Yes | model integrity + runtime prediction | Pass |
| OSINT enrichment | Yes | anomaly flow enrichment fields | Pass |
| Alert correlation | Yes | repeated flow trigger behavior | Pass |

### 9.2 Performance Result Table (Template)

| Scenario | Input Size / Duration | Flows Processed | Avg Processing Time | Notes |
|---|---:|---:|---:|---|
| Passive CSV small | ... | ... | ... | ... |
| Passive PCAP medium | ... | ... | ... | includes conversion |
| Active monitoring 5 min | ... | ... | ... | interface dependent |

### 9.3 Detection Quality Table (Template)

| Dataset/Test Case | RF Accuracy | IF Anomaly Rate | Avg Risk Score | Verified Threat % |
|---|---:|---:|---:|---:|
| Test Set A | ... | ... | ... | ... |
| Test Set B | ... | ... | ... | ... |

### 9.4 Alert Quality Table (Template)

| Test Scenario | Raw Alert Count | Correlated Alerts | Reduction % | Analyst Actionability |
|---|---:|---:|---:|---|
| Repeated scan bursts | ... | ... | ... | ... |

---

## 10) Figure Suggestions (for Final Paper)

1. System architecture diagram (frontend-backend-services-db-queue).
2. Passive upload processing sequence diagram.
3. Active monitoring loop diagram.
4. ML + OSINT fusion pipeline diagram.
5. Dashboard screenshot set (traffic trends + anomaly/OSINT pages).
6. Alert lifecycle and correlation diagram.

---

## 11) Correct Claims vs Claims to Phrase Carefully

### 11.1 Safe, Strong Claims (Fully Supported)

- NetGuard implements hybrid RF + IF detection.
- NetGuard supports both passive file analysis and active realtime monitoring.
- NetGuard enriches anomaly flows with OSINT and local threat feeds.
- NetGuard computes fused final scores and verdict tiers.
- NetGuard supports alert generation and correlation over time.

### 11.2 Claims to Phrase with Caution

- "Reduced false positives" should be stated as:
  - "designed to reduce false positives through validation fusion"
  - unless you provide quantitative before/after evidence.
- "Scalable" should be stated as:
  - "queue-based asynchronous design supports larger workloads"
  - unless you provide benchmark throughput numbers.
- "Real-time" should be stated as:
  - "near real-time monitoring with 5-second capture windows"
  - to remain precise.

---

## 12) Limitations (Include Honestly in Paper)

- Strict dependence on artifact/schema compatibility.
- PCAP processing depends on `cicflowmeter` availability.
- External OSINT rate limits and key availability can degrade enrichment depth.
- SQLite single-node architecture limits high-scale distributed deployment.
- No online retraining/adaptive drift correction in runtime path.
- Frontend lint quality debt exists and should be addressed for production hardening.

---

## 13) Future Work Roadmap

- Online/continual learning for model drift resilience.
- Adaptive threshold tuning based on environment baseline.
- Multi-node storage/message broker hardening (PostgreSQL/Kafka style evolution).
- Richer explainability dashboard (feature attribution and confidence decomposition).
- SIEM integration and automated response playbooks.
- Advanced adversarial robustness validation.

---

## 14) Reproducibility and Experiment Checklist

### 14.1 Setup Checklist

- Create/activate Python virtualenv.
- Install backend requirements.
- Install frontend dependencies.
- Configure environment keys (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, optional API key).
- Start backend and frontend.

### 14.2 Experiment Checklist

- Passive CSV test (known benign + attack samples).
- Passive PCAP/PCAPNG test.
- Active capture test (controlled traffic generation).
- OSINT enabled vs disabled comparison.
- Alert threshold sensitivity testing.
- Correlation-window behavior testing.
- Retention cleanup behavior verification.

### 14.3 Data to Log for Results

- total flows analyzed
- anomaly count
- risk distribution
- final verdict distribution
- alert count before/after correlation
- per-scenario processing latency
- queue status (redis/fallback)

---

## 15) Ready-to-Use Contribution Statement (Copy/Adapt)

NetGuard contributes a practical and integrated network threat-analysis framework that unifies dual-mode traffic ingestion, hybrid machine-learning detection, and intelligence-based threat validation in a single operational platform. Unlike isolated model demonstrations, NetGuard operationalizes the full detection lifecycle from ingestion to analyst-facing alerting and historical investigation, while preserving explainability through threat semantics, CVE mapping, and fused confidence verdicting.

---

## 16) Ready-to-Use Conclusion Paragraph (Copy/Adapt)

This work demonstrates that combining supervised classification, unsupervised anomaly detection, and threat-intelligence enrichment can provide a robust and operationally meaningful network defense workflow. NetGuard successfully implements this integration across passive and active monitoring modes, producing risk-scored and explainable outputs suitable for real-world analyst use. While external intelligence quotas and single-node persistence impose practical constraints, the architecture provides a strong foundation for future extensions in adaptive learning, distributed scaling, and automated incident response.

---

## 17) Quick Citation Map (Project Files to Reference in Report)

- System entry/API orchestration: `backend/app/main.py`
- Core detection and scoring: `backend/app/services/decision_service.py`
- OSINT and final fusion: `backend/app/services/osint.py`
- Local threat feeds: `backend/app/services/threat_feeds.py`
- Realtime packet processing: `backend/app/services/realtime_service.py`
- Queue subsystem: `backend/app/services/queue_service.py`, `backend/app/services/flow_queue.py`
- Persistence layer: `backend/app/db.py`
- Thresholds/CVE mapping: `backend/app/classification_config.py`
- Training pipeline: `training_pipeline/train.py`
- Frontend API integration: `frontend/src/services/api.js`
- Architecture docs: `docs/01_system_overview.md` to `docs/05_api_database_and_execution_flow.md`

---

## 18) Final Writing Advice

- Keep **claims evidence-driven**: connect every major claim to implementation and measured result.
- Distinguish clearly:
  - **implemented capability**
  - **observed result**
  - **future potential**
- Add at least one comparative experiment (with and without OSINT fusion) to strengthen novelty and impact.

