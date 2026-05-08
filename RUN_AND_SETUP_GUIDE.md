# NetGuard — Run & Setup Guide

This is the complete, step-by-step guide for taking a fresh machine from
zero to a running NetGuard instance. Follow it top-to-bottom and you will
have:

- a working backend on `http://localhost:8000`
- a working dashboard on `http://localhost:5173`
- live packet capture (optional) and PCAP/CSV upload analysis
- Docker-based deployment as an alternative to local install

> If you only want a quick reference, see `README.md`.
> This file is the exhaustive walkthrough.

---

## Table of contents

1. [System requirements](#1-system-requirements)
2. [Install OS-level prerequisites](#2-install-os-level-prerequisites)
3. [Get the source code](#3-get-the-source-code)
4. [Python virtual environment](#4-python-virtual-environment)
5. [Install Python dependencies](#5-install-python-dependencies)
6. [Install frontend dependencies](#6-install-frontend-dependencies)
7. [Configure environment variables](#7-configure-environment-variables)
8. [Obtain API keys (optional but recommended)](#8-obtain-api-keys-optional-but-recommended)
9. [Set up model artifacts](#9-set-up-model-artifacts)
10. [Optional: install Redis](#10-optional-install-redis)
11. [Optional: install cicflowmeter for PCAP support](#11-optional-install-cicflowmeter-for-pcap-support)
12. [Run the preflight check](#12-run-the-preflight-check)
13. [Run the backend](#13-run-the-backend)
14. [Run the frontend](#14-run-the-frontend)
15. [Run everything with Docker (alternative)](#15-run-everything-with-docker-alternative)
16. [Live (active) monitoring with sudo](#16-live-active-monitoring-with-sudo)
17. [Verify the app works end-to-end](#17-verify-the-app-works-end-to-end)
18. [Useful commands cheat sheet](#18-useful-commands-cheat-sheet)
19. [Project layout reference](#19-project-layout-reference)
20. [Troubleshooting](#20-troubleshooting)
21. [Where to find more documentation](#21-where-to-find-more-documentation)

---

## 1. System requirements

| Requirement       | Minimum                | Recommended            | Notes                                                             |
| ----------------- | ---------------------- | ---------------------- | ----------------------------------------------------------------- |
| Operating system  | Ubuntu 22.04 / Debian 12 / macOS 13 | Ubuntu 24.04 LTS  | Windows works only via WSL2 — install Ubuntu 22.04 inside WSL2. |
| CPU               | 2 cores                | 4+ cores               | RF inference is CPU-bound.                                        |
| RAM               | 4 GB                   | 8 GB                   | Loading `rf_model.pkl` (~80 MB) needs ~1 GB resident.             |
| Disk              | 5 GB free              | 20 GB free             | More if you store PCAP data or training datasets.                 |
| Network           | Outbound HTTPS         | Outbound HTTPS         | Needed for OSINT (AbuseIPDB / VirusTotal) and threat-feed refresh. |
| Privileges        | sudo                   | sudo                   | Required for live packet capture and OS-package installs.         |

You will also need:

- **Python 3.12.x** (`python3 --version` to check)
- **Node.js 20 LTS + npm** (`node --version`, `npm --version`)
- **Git** (`git --version`)
- **Docker + Docker Compose v2** *(optional, only if you choose §15)*

---

## 2. Install OS-level prerequisites

Choose the section matching your OS.

### 2a. Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y \
    python3 python3-venv python3-pip \
    nodejs npm \
    git curl \
    libpcap-dev gcc build-essential
```

Verify versions:

```bash
python3 --version    # expect 3.12.x
node --version       # expect v20.x
npm --version
git --version
```

If your distribution ships an older Python, install 3.12 via deadsnakes:

```bash
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.12 python3.12-venv
```

If your distribution ships an older Node, use NodeSource:

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

### 2b. macOS (Apple Silicon or Intel)

```bash
# install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

brew install python@3.12 node@20 git libpcap
brew link --force --overwrite node@20
```

### 2c. Windows (via WSL2)

1. Open PowerShell **as Administrator**:

   ```powershell
   wsl --install -d Ubuntu-22.04
   ```

2. Reboot, finish Ubuntu setup, then **inside WSL** follow §2a.

Native Windows is not supported because the project relies on `libpcap`
and POSIX paths.

---

## 3. Get the source code

```bash
# 1. Pick a working directory
mkdir -p ~/projects && cd ~/projects

# 2. Clone the main project (replace URL with the actual handoff URL)
git clone git@github.com:nalintern2026/nal.git
# or, if you don't have SSH set up:
# git clone https://github.com/nalintern2026/nal.git

cd nal
```

Optional — clone the **training dataset** (only if you want to retrain
models, see §9):

```bash
cd ~/projects
git clone https://github.com/nalintern2026/data.git nal-data
# Then symlink it into the expected path:
mkdir -p ~/projects/nal/training_pipeline/data/processed
ln -s ~/projects/nal-data/cic_ids \
      ~/projects/nal/training_pipeline/data/processed/cic_ids
```

---

## 4. Python virtual environment

The canonical project venv lives at `nal/.venv`. Always use it.

```bash
cd ~/projects/nal
python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .\.venv\Scripts\activate          # Windows PowerShell (WSL recommended)
```

When the venv is active your shell prompt will show `(.venv)`. To
deactivate later: `deactivate`.

> Do not create a second venv at `nal/backend/.venv`. Older docs/scripts
> referenced it but it is no longer needed.

---

## 5. Install Python dependencies

```bash
# inside nal/, with .venv active
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

This installs FastAPI, scikit-learn 1.8, pandas 3, scapy, cicflowmeter,
pytest, redis client, and all related libraries.

Sanity-check the install:

```bash
python -c "import fastapi, sklearn, pandas, scapy, scapy.all, redis, pytest; print('python deps OK')"
```

Expected output: `python deps OK`.

---

## 6. Install frontend dependencies

```bash
cd ~/projects/nal/frontend
npm install
cd ..
```

This installs React 18, Vite 5, axios, chart.js, lucide-react, tailwind,
ESLint, etc. It takes 1–3 minutes the first time.

Sanity-check:

```bash
cd frontend
npm run build
cd ..
```

You should see a successful Vite build with `dist/` produced.

---

## 7. Configure environment variables

The backend reads `nal/.env`. A template is provided at `nal/.env.example`.

```bash
cd ~/projects/nal
cp .env.example .env
```

Now open `.env` in your editor and set values:

| Variable                          | What to put                                                                 | Required?               |
| --------------------------------- | --------------------------------------------------------------------------- | ----------------------- |
| `NETGUARD_API_KEY`                | A long random string. **Must not** be empty or `change-me`.                 | **Yes**                 |
| `CORS_ALLOWED_ORIGINS`            | Defaults are fine for local dev. Change for production deploys.             | No                      |
| `NETGUARD_DATA_DIR`               | Leave commented to use the default `nal/data/`.                             | No                      |
| `DATABASE_URL`                    | Leave at `sqlite:///` — SQLite path is derived from `NETGUARD_DATA_DIR`.    | No                      |
| `DATA_RETENTION_DAYS`             | How many days of flow data to keep. Default `30`.                           | No                      |
| `ALERT_FINAL_SCORE_THRESHOLD`     | Alert trigger threshold (0–100). Default `70`.                              | No                      |
| `ALERT_CORRELATION_WINDOW_MINUTES`| Alert dedup window. Default `10`.                                           | No                      |
| `REDIS_URL`                       | `redis://localhost:6379` if Redis is running, else any value (auto-fallback). | No                      |
| `OSINT_ENABLED`                   | `true` to enable AbuseIPDB / VirusTotal lookups.                            | No                      |
| `OSINT_CACHE_TTL_SECONDS`         | Default `3600`.                                                             | No                      |
| `OSINT_MAX_RETRIES`               | Default `2`.                                                                | No                      |
| `OSINT_SKIP_NON_PUBLIC_IPS`       | `true` skips lookups for private/internal IPs.                              | No                      |
| `ABUSEIPDB_API_KEY`               | See §8.                                                                     | Recommended             |
| `VIRUSTOTAL_API_KEY`              | See §8.                                                                     | Recommended             |

### Generate a strong `NETGUARD_API_KEY`

Pick any of these:

```bash
# Option 1 (preferred): pure Python, no extra deps
python -c "import secrets; print(secrets.token_urlsafe(48))"

# Option 2: openssl
openssl rand -hex 32

# Option 3: uuid
python -c "import uuid; print(uuid.uuid4().hex + uuid.uuid4().hex)"
```

Paste the output into `.env`:

```
NETGUARD_API_KEY=<paste-here>
```

> Use the **same value** in the frontend if you want it to send the key
> automatically (see §14).

### Make sure `.env` never gets committed

It's already in `.gitignore`. Quick verification:

```bash
git check-ignore -v .env       # should print a matching rule
```

---

## 8. Obtain API keys (optional but recommended)

Without these keys the OSINT layer still runs locally (using internal
threat feeds) but external lookups will be skipped.

### 8a. AbuseIPDB

1. Visit <https://www.abuseipdb.com/account/api> and sign up (free).
2. Click **Create Key** → name it something like `netguard-dev`.
3. Copy the key into `.env`:

   ```
   ABUSEIPDB_API_KEY=<paste>
   ```

Free tier limit: 1,000 checks/day — fine for development.

### 8b. VirusTotal

1. Visit <https://www.virustotal.com/gui/join-us> and create a free account.
2. Click your avatar → **API key**.
3. Copy into `.env`:

   ```
   VIRUSTOTAL_API_KEY=<paste>
   ```

Free tier limit: 4 requests/minute, 500/day. The backend caches and
rate-limits automatically.

After saving `.env`, restart the backend if it's already running.

---

## 9. Set up model artifacts

The backend will refuse to perform inference if any artifact is missing.
There are 5 required files plus `metrics.json`:

```
training_pipeline/models/
├── metrics.json                       (~3 KB, tracked)
├── supervised/
│   └── rf_model.pkl                   (~80 MB, NOT tracked)
├── unsupervised/
│   └── if_model.pkl                   (~800 KB, tracked)
└── artifacts/
    ├── feature_names.pkl              (~2 KB, tracked)
    ├── label_encoder.pkl              (~0.3 KB, tracked)
    └── scaler.pkl                     (~4 KB, tracked)
```

When you clone the repo, **5 of the 6 files are already present** because
they ship in git. The exception is `rf_model.pkl`, which is too large.

### 9a. Get `rf_model.pkl`

Pick **one** of:

**Option A — Download the prebuilt model**

Replace `<URL>` with the link the previous developer shared (Drive,
S3, GitHub Release asset, etc.):

```bash
cd ~/projects/nal
mkdir -p training_pipeline/models/supervised
curl -L -o training_pipeline/models/supervised/rf_model.pkl <URL>
```

**Option B — Retrain locally** (requires the dataset from §3)

```bash
cd ~/projects/nal
source .venv/bin/activate
python training_pipeline/train.py
```

Training takes ~5–15 minutes depending on the machine and dataset size.
On completion all artifacts (including `rf_model.pkl`) will be written
into `training_pipeline/models/`.

### 9b. Verify

```bash
ls -lh training_pipeline/models/supervised/rf_model.pkl
# expected: -rw-r--r-- ... ~80M ... rf_model.pkl
```

The preflight check in §12 also validates this.

---

## 10. Optional: install Redis

NetGuard works without Redis (it falls back to an in-process queue), but
Redis is recommended for production-style runs.

### Install

```bash
# Ubuntu / Debian
sudo apt install -y redis-server
sudo systemctl enable --now redis-server

# macOS
brew install redis
brew services start redis
```

### Verify

```bash
redis-cli ping     # expected: PONG
```

### Configure NetGuard

In `nal/.env`:

```
REDIS_URL=redis://localhost:6379
```

Restart the backend. You should see queue-related logs reference Redis
instead of the in-process worker.

---

## 11. Optional: install cicflowmeter for PCAP support

`cicflowmeter` is a Python tool that converts PCAP/PCAPNG files into
CIC-IDS-style flow CSVs. It's already in `requirements.txt`, but you
should confirm the binary is on your PATH:

```bash
source .venv/bin/activate
which cicflowmeter   # expected: ~/projects/nal/.venv/bin/cicflowmeter
cicflowmeter --help
```

If it isn't found:

```bash
pip install --force-reinstall cicflowmeter
```

If you want to point the backend at a system-wide install instead:

```bash
export CICFLOWMETER_BIN=/usr/local/bin/cicflowmeter
```

PCAP support is needed when you upload `.pcap` / `.pcapng` files **and**
when training from raw captures. CSV uploads do not need it.

---

## 12. Run the preflight check

This script audits the entire setup in one shot.

```bash
cd ~/projects/nal
./preflight_check.sh
```

Expected outcome on a healthy install:

```
==== Preflight summary ====
PASS: 22
WARN: 0–2
FAIL: 0

Result: READY - all checks passed.
```

If you see `FAIL`, fix that item before continuing. Common ones:

- `NETGUARD_API_KEY is unset or default` — see §7.
- `Random Forest model exists` — see §9.
- `cicflowmeter is not installed` — see §11 (warning, not blocking).

---

## 13. Run the backend

Open a terminal:

```bash
cd ~/projects/nal
source .venv/bin/activate
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

You should see logs ending with something like:

```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process ...
INFO:     Started server process ...
INFO:     Application startup complete.
```

Smoke-test from another terminal:

```bash
curl http://127.0.0.1:8000/api/health
```

Expected: a JSON envelope with `"status":"SUCCESS"` (or `"DEGRADED"` if
optional pieces are missing).

Other useful unauthenticated endpoints:

```bash
curl http://127.0.0.1:8000/api/integrity
curl http://127.0.0.1:8000/api/model/integrity
```

All other `/api/*` routes require:

```
x-api-key: <your NETGUARD_API_KEY>
```

Example:

```bash
curl -H "x-api-key: $NETGUARD_API_KEY" http://127.0.0.1:8000/api/dashboard/stats
```

To stop: `Ctrl+C` in the backend terminal.

---

## 14. Run the frontend

In a **second** terminal (keep the backend running):

```bash
cd ~/projects/nal/frontend
npm run dev -- --host
```

Output:

```
  VITE v5.x.x  ready in xxx ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: http://192.168.x.x:5173/
```

Open <http://localhost:5173> in your browser.

### Send the API key from the frontend

If you set `NETGUARD_API_KEY` in the backend, also add the same value to
the frontend so it can reach protected endpoints:

```bash
cd ~/projects/nal/frontend
cat > .env.local <<'EOF'
VITE_API_URL=http://127.0.0.1:8000/api
VITE_NETGUARD_API_KEY=<paste-the-same-value-as-backend>
EOF
```

Restart `npm run dev` after changing `.env.local`.

> `frontend/.env.local` is git-ignored automatically.

---

## 15. Run everything with Docker (alternative)

If you prefer a single-command run, Docker is fully supported.

### Prerequisites

```bash
# Ubuntu / Debian
sudo apt install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER     # log out & back in once
```

### One-time setup

```bash
cd ~/projects/nal
cp .env.example .env
# edit .env (see §7); also place rf_model.pkl per §9
```

### Start the stack

```bash
docker compose up --build
```

This builds two images:

- **backend** — exposes <http://localhost:8000>
- **frontend** — exposes <http://localhost:5173>

Stop with `Ctrl+C`, then `docker compose down` to clean up containers.

### Persistent data

`docker-compose.yml` mounts `./data:/app/data`, so SQLite databases and
uploads survive container restarts inside `nal/data/`.

### Live capture inside Docker

For active monitoring inside Docker, the backend container needs
elevated network privileges. Add to the `backend:` service in
`docker-compose.yml` (only when you actually need live capture):

```yaml
    cap_add:
      - NET_ADMIN
      - NET_RAW
    network_mode: host
```

Note: with `network_mode: host`, you must also drop the `ports:` mapping
for that service.

---

## 16. Live (active) monitoring with sudo

The **Active Monitoring** page captures real packets from a network
interface. Linux requires raw-socket privileges.

```bash
cd ~/projects/nal/backend
sudo ../.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Equivalent (running from the project root):

```bash
cd ~/projects/nal
sudo .venv/bin/python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

In the frontend, navigate to **Active Monitoring**, choose an interface
(`eth0`, `wlan0`, `lo`, etc.), and click **Start**. Stop with the same
button when done; a session summary will be saved to history.

### Avoiding sudo every time

You can grant the venv's Python the `cap_net_raw` capability so sudo
isn't needed:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ~/projects/nal/.venv/bin/python3.12
```

Re-run after any `pip` reinstall.

---

## 17. Verify the app works end-to-end

After §13 + §14 (or §15) are running:

1. Open <http://localhost:5173> — the **Dashboard** loads with the
   sidebar visible. The top-right indicator should show `connected` (green).
2. Go to **Upload** → drop a CSV from `training_pipeline/data/processed/cic_ids/flows/monday/`
   (if you have the dataset) or any CIC-style flow CSV.
3. Wait for the upload job to complete. The **Anomalies**, **Traffic
   Analysis**, and **OSINT Validation** pages should populate.
4. Open **Model Performance** — the loaded artifacts (RF, IF) should
   show as `active`.
5. Open **SBOM Security** → upload a `requirements.txt` or `package.json`
   and verify the dependency scan completes and lists OSV vulnerabilities.
6. (Optional) **Active Monitoring** — start a capture (sudo required),
   wait 30 seconds, stop. Flows should appear in **History** as an
   active session.

If all six steps work, the install is complete.

---

## 18. Useful commands cheat sheet

```bash
# ── Activate the project venv ──────────────────────────────
source ~/projects/nal/.venv/bin/activate

# ── Run the backend in dev mode ────────────────────────────
cd ~/projects/nal
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

# ── Run the backend with sudo (live capture) ───────────────
cd ~/projects/nal
sudo .venv/bin/python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000

# ── Run the frontend in dev mode ───────────────────────────
cd ~/projects/nal/frontend
npm run dev -- --host

# ── Build the frontend for production ──────────────────────
cd ~/projects/nal/frontend
npm run build

# ── Run backend tests ──────────────────────────────────────
cd ~/projects/nal
.venv/bin/python -m pytest backend/tests

# ── Lint the frontend ──────────────────────────────────────
cd ~/projects/nal/frontend
npm run lint

# ── Validate the entire setup ──────────────────────────────
cd ~/projects/nal
./preflight_check.sh

# ── Retrain the ML pipeline ────────────────────────────────
cd ~/projects/nal
.venv/bin/python training_pipeline/train.py

# ── Reset the SQLite database ──────────────────────────────
rm -rf ~/projects/nal/data/flows.db* ~/projects/nal/data/passive_timeline.db*
# next backend start will recreate empty schema

# ── Docker stack ───────────────────────────────────────────
cd ~/projects/nal
docker compose up --build           # start
docker compose down                 # stop & remove
docker compose logs -f backend      # tail backend logs
```

---

## 19. Project layout reference

```
nal/                                  ← repository root
├── backend/                          ← FastAPI server
│   ├── app/
│   │   ├── main.py                   ← app factory + routes
│   │   ├── config.py                 ← env-driven config
│   │   ├── paths.py                  ← canonical filesystem paths
│   │   ├── db.py                     ← SQLite layer
│   │   ├── classification_config.py  ← threat → CVE mapping
│   │   ├── osint_routes.py           ← OSINT API surface
│   │   ├── services/
│   │   │   ├── decision_service.py   ← RF + IF inference engine
│   │   │   ├── realtime_service.py   ← live packet capture
│   │   │   ├── osint.py              ← AbuseIPDB / VirusTotal client
│   │   │   ├── threat_feeds.py       ← local threat feed refresher
│   │   │   ├── queue_service.py      ← Redis queue
│   │   │   ├── flow_queue.py         ← in-process queue fallback
│   │   │   ├── sbom_service.py       ← SBOM dependency scanner
│   │   │   ├── integrity_service.py  ← runtime integrity checks
│   │   │   └── model_integrity.py    ← model artifact validation
│   │   └── utils/
│   ├── tests/
│   │   └── test_api.py
│   └── Dockerfile
│
├── frontend/                         ← React + Vite dashboard
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/Layout.jsx
│   │   ├── pages/                    ← Dashboard, Upload, etc.
│   │   └── services/api.js
│   ├── package.json
│   ├── vite.config.js
│   └── Dockerfile
│
├── core/
│   └── feature_engineering.py        ← shared feature pipeline
│
├── training_pipeline/
│   ├── train.py                      ← model training entry point
│   ├── preprocessing/
│   ├── data_collection/
│   ├── data/                         ← (gitignored) raw + processed CSV/PCAP
│   └── models/
│       ├── metrics.json
│       ├── supervised/rf_model.pkl   ← (NOT tracked, ~80 MB)
│       ├── unsupervised/if_model.pkl
│       └── artifacts/
│           ├── scaler.pkl
│           ├── label_encoder.pkl
│           └── feature_names.pkl
│
├── data/                             ← (gitignored, runtime) flows.db, temp_uploads/
├── docs/                             ← in-depth architecture docs
├── docker-compose.yml
├── preflight_check.sh
├── requirements.txt
├── .env.example
├── .gitignore
├── .dockerignore
├── README.md
└── RUN_AND_SETUP_GUIDE.md            ← this file
```

---

## 20. Troubleshooting

### Backend won't start

| Symptom in logs                                            | Cause / fix                                                                       |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `ModuleNotFoundError: No module named 'app'`               | Run uvicorn from `nal/` (not `backend/`), or set `PYTHONPATH=backend`.            |
| `MODEL_UNAVAILABLE: model artifacts are missing`           | Run §9. Verify `rf_model.pkl` exists.                                             |
| `Address already in use` on port 8000                      | Another process is using 8000: `sudo lsof -i :8000` then kill, or pick a new `--port`. |
| `permission denied` opening `data/flows.db`                | `sudo chown -R $USER ~/projects/nal/data`.                                         |
| `redis.exceptions.ConnectionError`                         | Redis isn't running. Either start it (§10) or ignore — backend falls back automatically. |
| `RuntimeError: Unable to connect to SQLite database`       | The data dir doesn't exist or isn't writable. Re-run `./preflight_check.sh`.      |

### Backend starts, but frontend can't reach it

| Symptom                                              | Cause / fix                                                                                |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Sidebar shows "API offline" or "disconnected"        | Backend not running, wrong port, or CORS blocking. Check `nal/.env` `CORS_ALLOWED_ORIGINS`. |
| `401 Missing API key` in DevTools                    | Set `VITE_NETGUARD_API_KEY` in `frontend/.env.local` (see §14) and restart `npm run dev`.   |
| `Network Error` for `/api/*`                         | Check `vite.config.js` proxy or set `VITE_API_URL` in `frontend/.env.local`.                |
| CORS error in browser console                        | Add the frontend origin to `CORS_ALLOWED_ORIGINS` in `nal/.env` and restart backend.        |

### Upload fails

| Symptom                                              | Cause / fix                                                                          |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Upload returns 413 / file too large                  | Increase `UPLOAD_MAX_FILE_SIZE_BYTES` in `nal/.env` (default 200 MB).                |
| Upload accepted but job ends as `FAILED`             | Look at `backend/.../uvicorn` logs. Usually missing model artifact or schema mismatch. |
| `cicflowmeter not found` for PCAP uploads            | See §11.                                                                             |

### Active monitoring fails

| Symptom                                              | Cause / fix                                                                          |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `Permission denied` opening interface                | Backend not running with raw-socket privileges. See §16.                              |
| Interface dropdown is empty                          | `scapy` couldn't enumerate interfaces. Run with sudo.                                 |
| Capture starts but no packets flow                   | Wrong interface chosen, or the interface has no traffic. Try `lo` and `ping localhost`. |

### Docker issues

| Symptom                                              | Cause / fix                                                                          |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `permission denied` connecting to docker daemon      | Add user to docker group: `sudo usermod -aG docker $USER`, then log out/in.           |
| Builds skip newest changes                           | `docker compose build --no-cache backend`.                                            |
| Frontend in browser can't reach backend              | The `VITE_API_URL` in `docker-compose.yml` must point to a host the **browser** can resolve, normally `http://localhost:8000/api`. |

### Tests fail

| Symptom                                              | Cause / fix                                                                          |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `No module named pytest` when running tests          | You ran system `python3` instead of the venv. Use `.venv/bin/python -m pytest backend/tests`. |
| Tests fail with `MODEL_UNAVAILABLE`                  | Place model artifacts as in §9.                                                       |

---

## 21. Where to find more documentation

| Topic                           | File                                          |
| ------------------------------- | --------------------------------------------- |
| Project overview                | `docs/01_system_overview.md`                  |
| Architecture and dataflow       | `docs/02_architecture_and_dataflow.md`        |
| Machine learning details        | `docs/03_machine_learning_and_detection.md`   |
| OSINT, CVE, SBOM intelligence   | `docs/04_intelligence_layers_osint_cve_sbom.md` |
| API surface + DB schema         | `docs/05_api_database_and_execution_flow.md`  |
| Research-paper-style write-up   | `docs/99_research_paper_ultimate_guide.md`    |

---

## Quick "I just want it running" recipe

```bash
git clone git@github.com:nalintern2026/nal.git
cd nal

python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip && pip install -r requirements.txt

cd frontend && npm install && cd ..

cp .env.example .env
python -c "import secrets; print('NETGUARD_API_KEY=' + secrets.token_urlsafe(48))" >> .env

# Place rf_model.pkl into training_pipeline/models/supervised/
# (see §9 — download or retrain)

./preflight_check.sh

# Terminal 1
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2
cd frontend && npm run dev -- --host

# open http://localhost:5173
```

---

If anything in this guide drifts from the actual repo, treat the code
and `preflight_check.sh` as the source of truth and update this file.
