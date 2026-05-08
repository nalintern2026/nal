# NetGuard — Network Security Intelligence

NetGuard is a full-stack network traffic security analysis platform. It combines a FastAPI backend, ML-based flow classification, OSINT/CVE enrichment, and a React dashboard to inspect both uploaded captures and live traffic.

This document is the **single source of truth for setting up and running the project on a fresh machine**.

---

## 1. What's in this repository

```
nal/
├── backend/                # FastAPI app, services, tests
├── frontend/               # React + Vite dashboard
├── core/                   # Feature engineering shared by backend & training
├── training_pipeline/      # Model training scripts + model artifacts
├── docs/                   # Architecture / ML / API documentation
├── docker-compose.yml      # One-command Docker stack
├── preflight_check.sh      # Sanity check before running
├── requirements.txt        # Python dependencies (single source)
├── .env.example            # Environment variable template
└── README.md               # This file
```

The training **dataset** (CIC-IDS 2017 processed flows) lives in a separate
GitHub repository because it is too large to commit here. Instructions for
attaching it are in §5.

---

## 2. Prerequisites

Install once on a Linux/macOS machine:

| Tool                 | Version           | Notes                                                                 |
| -------------------- | ----------------- | --------------------------------------------------------------------- |
| Python               | 3.12.x            | The `requirements.txt` is pinned for 3.12.                            |
| Node.js + npm        | Node 20 LTS       | Used to build/run the React frontend.                                 |
| Docker + Compose     | latest            | Optional, only if you want the containerized run.                     |
| `libpcap` headers    | OS package        | Required by `scapy` / `cicflowmeter`. On Debian/Ubuntu: `sudo apt install libpcap-dev`. |
| Redis                | 6+                | **Optional.** If absent, the backend falls back to an in-process queue. |

---

## 3. First-time setup (local, no Docker)

All commands assume your shell is in the repo root (the `nal/` directory).

```bash
# 1) Create the project virtualenv (canonical path is nal/.venv)
python3 -m venv .venv
source .venv/bin/activate

# 2) Install backend + ML + tooling dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3) Install frontend dependencies
cd frontend
npm install
cd ..

# 4) Create your local .env from the template
cp .env.example .env

# 5) Open .env and fill in:
#    - NETGUARD_API_KEY       (any random string, must NOT be empty/"change-me")
#    - ABUSEIPDB_API_KEY      (optional, enables AbuseIPDB lookups)
#    - VIRUSTOTAL_API_KEY     (optional, enables VirusTotal lookups)
#    Everything else can stay at defaults.
```

> **Single virtualenv policy.** Always use `nal/.venv`. Do **not** create a
> second `nal/backend/.venv`; older docs/scripts referenced it but the
> canonical environment is the one at `nal/.venv`.

---

## 4. Model artifacts

The backend refuses to run inference without all five artifacts being present
and compatible. They live under `training_pipeline/models/`:

| File                                       | Tracked in repo? | Notes                                                |
| ------------------------------------------ | ---------------- | ---------------------------------------------------- |
| `models/artifacts/scaler.pkl`              | yes              | small (≈ 4 KB)                                       |
| `models/artifacts/label_encoder.pkl`       | yes              | small                                                |
| `models/artifacts/feature_names.pkl`       | yes              | small                                                |
| `models/unsupervised/if_model.pkl`         | yes              | ≈ 800 KB                                             |
| `models/metrics.json`                      | yes              | training metrics summary                             |
| `models/supervised/rf_model.pkl`           | **no** (~80 MB)  | obtain separately — see below                        |

### Getting `rf_model.pkl`

Pick **one** of:

1. **Download** the prebuilt `rf_model.pkl` from the project handoff package
   (e.g. shared drive / GitHub release) and place it at:
   ```
   training_pipeline/models/supervised/rf_model.pkl
   ```

2. **Retrain** locally. This requires the CIC-IDS 2017 processed flows.
   Clone the dataset repository alongside this project:
   ```bash
   # outside nal/
   git clone https://github.com/nalintern2026/data.git
   # link the dataset into the expected path
   ln -s "$(pwd)/data/cic_ids" /path/to/nal/training_pipeline/data/processed/cic_ids
   ```
   Then run:
   ```bash
   cd nal
   source .venv/bin/activate
   python training_pipeline/train.py
   ```
   The script writes all artifacts (including `rf_model.pkl`) into
   `training_pipeline/models/`.

After placing the file, verify with:
```bash
./preflight_check.sh
```
You should see `[PASS] Random Forest model exists ...`.

---

## 5. Running the application (local)

Open two terminals.

**Terminal 1 — backend**

```bash
cd nal
source .venv/bin/activate
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — frontend**

```bash
cd nal/frontend
npm run dev -- --host
```

Then open <http://localhost:5173> in your browser. The frontend talks to the
backend at `http://127.0.0.1:8000/api` by default.

### Live (active) monitoring

Live packet capture needs raw-socket privileges. Run the backend with `sudo`
when you want to use the **Active Monitoring** page:

```bash
cd nal/backend
sudo .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

> Replace `.venv` with `../.venv` if you only have the canonical project
> virtualenv and not a backend-local one.

### Optional Redis queue

If a Redis server is running at the URL in `REDIS_URL` (default
`redis://localhost:6379`), the backend uses it for batched flow inserts.
Otherwise it transparently falls back to an in-process queue — no action
required.

---

## 6. Running the application (Docker)

```bash
cd nal
cp .env.example .env       # edit values first
docker compose up --build
```

- Backend: <http://localhost:8000>
- Frontend: <http://localhost:5173>

Notes:
- `docker-compose.yml` pins `NETGUARD_DATA_DIR=/app/data` and mounts a
  host-side `./data` directory, so SQLite databases and uploads persist
  across container restarts inside `nal/data/`.
- The `.env` file is read via `env_file:` and is **not** baked into the
  image (`.dockerignore` excludes it).

---

## 7. Verify everything is wired up

A scripted preflight check is included. Run it once after setup:

```bash
cd nal
./preflight_check.sh
```

A clean run prints `Result: READY - all checks passed.` It will warn if
`cicflowmeter` is missing (only required to convert PCAP → CSV) and fail if
`NETGUARD_API_KEY` is unset or still `change-me`.

You can also smoke-test the backend:

```bash
.venv/bin/python -m pytest backend/tests
```

---

## 8. Where the runtime data lives

By default everything writable is rooted at `nal/data/`:

```
nal/data/
├── flows.db                # main operational SQLite DB
├── flows.db-shm / -wal     # SQLite WAL sidecar files
├── passive_timeline.db     # dashboard timeline DB
└── temp_uploads/           # staged uploads (PCAP/PCAPNG/CSV/dependency manifests)
```

To put data elsewhere, set `NETGUARD_DATA_DIR=/absolute/path` in `.env`.

All of the above is `.gitignore`d — fresh clones start with an empty data
directory, populated on first run.

---

## 9. Optional: PCAP support

To analyze `.pcap` / `.pcapng` files (passive uploads or training conversions),
install `cicflowmeter` into the project venv:

```bash
source .venv/bin/activate
pip install cicflowmeter
```

(The package is already listed in `requirements.txt`, so this happens by
default. The preflight check will warn if it isn't on `PATH`.)

---

## 10. Security baseline

- All `/api/*` routes (except `/api/health`, `/api/model/integrity`,
  `/api/integrity`) require an `x-api-key` header equal to
  `NETGUARD_API_KEY`. Set the same value in the frontend `.env` as
  `VITE_NETGUARD_API_KEY` if you want the React app to send it
  automatically.
- Never commit `.env`. Only `.env.example` is tracked.
- `.dockerignore` excludes `.env*` so secrets never end up in images.

---

## 11. Documentation

In-depth documentation lives under [`docs/`](./docs):

- `docs/01_system_overview.md` — high-level system overview
- `docs/02_architecture_and_dataflow.md` — services, queues, dataflow
- `docs/03_machine_learning_and_detection.md` — RF + IF pipeline
- `docs/04_intelligence_layers_osint_cve_sbom.md` — OSINT, CVE, SBOM
- `docs/05_api_database_and_execution_flow.md` — REST surface + DB schema
- `docs/99_research_paper_ultimate_guide.md` — research-paper-style write-up

---

## 12. Quick troubleshooting

| Symptom                                                | Likely cause                                                                            |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------- |
| Backend logs `MODEL_UNAVAILABLE` on upload             | `rf_model.pkl` is missing — see §4.                                                     |
| Frontend shows "API offline"                           | Backend not running, or `VITE_API_URL` / `NETGUARD_API_KEY` mismatch.                    |
| `401 Missing/Invalid API key`                          | Set `VITE_NETGUARD_API_KEY` in `frontend/.env.local` to the same value as the backend.  |
| `cicflowmeter not found` when uploading PCAP           | `pip install cicflowmeter` inside `nal/.venv` (or run inside Docker which ships it).     |
| Active Monitoring shows "permission denied"            | Backend is not running with raw-socket privileges — restart with `sudo` (see §5).        |
| Files appear at `~/Desktop/Network/flows.db` etc.      | You're on an older clone whose `paths.py` defaulted to the workspace root. Pull latest. |
