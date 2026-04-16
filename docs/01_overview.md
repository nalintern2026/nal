# NetGuard Project Overview

## Purpose and Problem Statement

This repository implements an end-to-end network security intelligence system centered on the `nal` application. It is designed to analyze network traffic flows, classify known attack types, detect anomalous behavior, assign risk levels, and expose results through APIs, dashboards, and automation workflows.

The practical problem it solves is operational security visibility: transforming raw packet captures or live packet streams into actionable threat insights with clear severity and context.

## Key Features

- Hybrid ML decision pipeline (supervised + unsupervised) for flow classification and anomaly detection.
- Dual ingestion modes:
  - passive analysis from uploaded `.pcap`, `.pcapng`, and `.csv` files,
  - active live monitoring via Scapy capture windows.
- Flow-level risk scoring and risk-level mapping (`Critical`, `High`, `Medium`, `Low`).
- Threat-to-CVE contextual mapping and classification reason generation.
- Persistent storage in SQLite (`flows.db`) for flows and analysis history, plus `passive_timeline.db` for passive dashboard timeline points.
- React dashboard for monitoring, anomaly triage, historical reports, model metrics, and SBOM security.
- SBOM analysis for uploaded dependency manifests with vulnerability enrichment from OSV.
- n8n automation workflows for health checks, alerting, periodic reports, training checks, and monitor control.

## Target Users and Use Cases

- Security analysts investigating suspicious traffic patterns and risk trends.
- SOC-like operators monitoring active/passive network telemetry.
- ML/security engineers iterating on model training and validation.
- Reviewers/mentors evaluating architecture clarity and operational readiness.

Typical use cases:

- Upload a capture and quickly get threat distribution plus top risky flows.
- Run live monitoring on an interface and continuously populate active-flow telemetry.
- Generate daily security summaries and automated alerts via n8n.
- Scan dependency files to identify vulnerable packages and remediation paths.

## High-Level Workflow

1. Traffic enters the system (file upload or live capture).
2. Flows are represented in CIC-like feature format.
3. The decision engine applies preprocessing + model inference.
4. Risk/threat context is attached to each flow.
5. Results are persisted in SQLite and surfaced via API.
6. Frontend and n8n workflows consume API outputs for UI and automation.

## System Behavior Summary

- **Real-time behavior:** active monitoring loop captures every ~5 seconds, classifies, and inserts new flows.
- **Batch behavior:** uploaded files are processed in CSV chunks (default 50,000 rows) to control memory.
- **Fallback behavior:** if trained supervised artifacts are missing, the system still runs unsupervised anomaly detection with BENIGN fallback labels and adjusted risk logic.
- **Data retention behavior:** persistent flow/history data is stored in root-level `flows.db` and passive timeline snapshots in `passive_timeline.db`; uploaded raw files are processed then removed from temporary locations.
