# NetGuard Network Security Intelligence

NetGuard is a full-stack network traffic security analysis platform in this repository under `nal/`. It combines FastAPI services, machine-learning inference, realtime packet monitoring, and a React dashboard to classify traffic, detect anomalies, score risk, and generate operational reports.

## Key Features

- Hybrid flow analysis using Random Forest + Isolation Forest.
- Passive upload pipeline for `.pcap`, `.pcapng`, and `.csv` files.
- Active live-monitoring pipeline using Scapy capture windows.
- Risk scoring, threat labeling, CVE-context mapping, and analysis history.
- SBOM dependency scanning with OSV vulnerability enrichment.
- Integrity endpoints for model/runtime/database validation.

## Minimal Setup

```bash
cd /home/ictd/Desktop/Network/nal
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cd frontend
npm install
```

## Minimal Run

Backend:

```bash
cd /home/ictd/Desktop/Network/nal
source .venv/bin/activate
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

Frontend:

```bash
cd /home/ictd/Desktop/Network/nal/frontend
npm run dev -- --host
```

## Documentation

👉 Full documentation available in `/docs`

## Security Baseline

- Protected API routes require `x-api-key` header matching `NETGUARD_API_KEY`.
- Public diagnostic routes: `/api/health`, `/api/model/integrity`, `/api/integrity`.

- `docs/01_overview.md`
- `docs/02_architecture.md`
- `docs/03_folder_structure.md`
- `docs/04_modules.md`
- `docs/05_dataflow.md`
- `docs/06_setup.md`
- `docs/07_execution.md`
- `docs/08_testing_validation.md`
- `docs/09_ml_model.md`
- `docs/10_alerting.md`
- `docs/11_api.md`
- `docs/12_troubleshooting.md`
- `docs/13_dev_notes.md`
- `docs/14_live_monitoring.md`