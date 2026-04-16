# Setup Guide

## Prerequisites

- Linux environment (project is currently configured and tested in Linux paths).
- Python 3.12 (container uses `python:3.12-slim`).
- Node.js 20+ and npm (frontend tooling).
- Optional but recommended: Docker + Docker Compose.
- For live monitoring: elevated privileges (`sudo`) for packet capture.

## Repository Layout Note

The runnable application is inside `nal/`, while runtime DB (`flows.db`) is at repository root.

## Backend Setup

```bash
cd /home/ictd/Desktop/Network/nal
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Frontend Setup

```bash
cd /home/ictd/Desktop/Network/nal/frontend
npm install
```

## Environment Variables

### Backend / n8n-related examples

Use `nal/.env.example` as baseline:

- `ALERT_WEBHOOK_URL`
- `ANOMALY_RATE_THRESHOLD`
- `RISK_SCORE_THRESHOLD`
- `CRITICAL_COUNT_THRESHOLD`
- `NETGUARD_AUTO_RESTART`
- `NETGUARD_EXPECT_RUNNING`
- `NETGUARD_DEFAULT_INTERFACE`

### Frontend

- `VITE_API_URL` (defaults to `http://127.0.0.1:8000/api` in `api.js` if not set).

## External Services

- OSV API is queried by SBOM scanner (internet access required for vulnerability enrichment).
- Slack/webhook endpoint is required for n8n alert/report delivery.

## Docker-Based Setup (Optional)

From `nal/`:

```bash
docker compose up --build
```

Exposed services:

- Backend: `8000`
- Frontend: `5173`
- n8n: `5678`

## Data/Model Preparation

If you need model artifacts before inference:

```bash
cd /home/ictd/Desktop/Network/nal
.venv/bin/python3 training_pipeline/train.py
```

This writes models/artifacts into `nal/training_pipeline/models`.
