# NAL Deployment Guide — Run on Another Server

This guide walks through setting up and running the NAL (Network Anomaly detection and monitoring) application on a new server: dependencies, paths, commands, and configuration.

---

## 1. Directory Layout (Important)

The backend resolves paths relative to the **folder that contains the `nal` directory**. That folder is the **project root** for the database and uploads.

```
<PROJECT_ROOT>/
├── nal/
│   ├── backend/          # FastAPI app
│   ├── frontend/         # React + Vite UI
│   ├── core/             # Shared feature_engineering (used by backend + training)
│   ├── training_pipeline/
│   │   └── models/       # Required: supervised/, unsupervised/, artifacts/
│   ├── temp_processing/  # Created at runtime (PCAP→CSV processing)
│   └── docs/
├── flows.db              # Created at runtime (SQLite DB)
└── temp_uploads/         # Created at runtime (PCAP/CSV uploads)
```

- **Database:** `flows.db` is created in `<PROJECT_ROOT>`, i.e. **one level above** the `nal` folder.
- **Models:** Backend expects `<PROJECT_ROOT>/nal/training_pipeline/models/` with subdirs `supervised/`, `unsupervised/`, and `artifacts/` (e.g. `if_model.pkl`, `scaler.pkl`, `feature_names.pkl`). If you only have a copy of the repo without trained models, you must train or copy the `training_pipeline/models` tree from a machine that has already run training.
- **Temp dirs:** `temp_uploads` and `temp_processing` are created automatically when needed; they live in project root and inside `nal` respectively (see backend code).

When you clone or copy the repo, ensure the **parent directory of `nal`** is writable by the user running the backend (for `flows.db` and `temp_uploads`).

---

## 2. Prerequisites

- **OS:** Linux (recommended; packet capture for Active Monitoring works best here).
- **Python:** 3.10 or 3.11 (recommended). Check with `python3 --version`.
- **Node.js:** v18+ (for building/serving the frontend). Check with `node -v` and `npm -v`.
- **Optional (for PCAP upload analysis):** `libpcap-dev` so the `cicflowmeter` pip package can work (e.g. `sudo apt-get install libpcap-dev` on Debian/Ubuntu).
- **Active Monitoring (live packet capture):** Backend must run with **root/sudo** so it can open raw sockets. Use: `sudo .venv/bin/python -m uvicorn ...`.

---

## 3. Getting the Code

Clone or copy the repository so that the **parent of the `nal` folder** is your project root.

**Option A — Git**

```bash
# Example: deploy into /opt/nal-app
sudo mkdir -p /opt/nal-app
sudo chown "$USER" /opt/nal-app
cd /opt/nal-app
git clone <YOUR_REPO_URL> nal
# If the repo root is the nal folder itself, you now have /opt/nal-app/nal/...
# PROJECT_ROOT = /opt/nal-app
```

**Option B — Copy from another machine**

Copy the whole tree so that you have:

- `<PROJECT_ROOT>/nal/` with `backend/`, `frontend/`, `core/`, `training_pipeline/`, etc.
- Optionally copy an existing `flows.db` and/or `training_pipeline/models/` from the source machine into `<PROJECT_ROOT>/flows.db` and `<PROJECT_ROOT>/nal/training_pipeline/models/`.

---

## 4. Backend Setup

### 4.1 Python virtual environment and dependencies

From the **backend** directory (so that `nal` is the parent of `backend`):

```bash
cd <PROJECT_ROOT>/nal/backend
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

This installs FastAPI, uvicorn, scapy, pandas, scikit-learn, cicflowmeter, and the rest. The backend uses the `core` and `training_pipeline` that live in `<PROJECT_ROOT>/nal/`, so run the backend from `<PROJECT_ROOT>/nal/backend` (or ensure Python path includes the project root; the code uses `Path(__file__).resolve()` so running from `nal/backend` is enough).

### 4.2 Paths the backend expects (no config file)

- **DB:** `<PROJECT_ROOT>/flows.db` (parent of `nal`).
- **Models:** `<PROJECT_ROOT>/nal/training_pipeline/models/` (supervised, unsupervised, artifacts).
- **CICFlowMeter:** Uses the same venv as the backend (e.g. `nal/backend/.venv/bin/cicflowmeter`) when converting PCAP to CSV for file uploads.

No environment variables are required for the backend to find DB or models; they are derived from the source file paths.

### 4.3 Running the backend

From `<PROJECT_ROOT>/nal/backend`:

**Development (bind to all interfaces so other machines can reach the API):**

```bash
cd <PROJECT_ROOT>/nal/backend
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**With Active Monitoring (packet capture) — must run with sudo:**

```bash
cd <PROJECT_ROOT>/nal/backend
sudo .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Replace `<PROJECT_ROOT>` with the actual path (e.g. `/opt/nal-app`). Example:

```bash
cd /opt/nal-app/nal/backend
sudo .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

- **Port:** Default is 8000. The frontend will call this URL; set `VITE_API_URL` to match (see below).
- **Firewall:** If other hosts need to access the UI or API, open ports 8000 (API) and, if you serve the frontend on the same server, 5173 (dev) or the port where you serve the built frontend.

---

## 5. Frontend Setup

### 5.1 Install dependencies and build

```bash
cd <PROJECT_ROOT>/nal/frontend
npm install
```

**For production:** Build the frontend with the API URL that the browser will use to call the backend. This is baked in at build time via `VITE_API_URL`:

```bash
cd <PROJECT_ROOT>/nal/frontend
export VITE_API_URL=http://YOUR_SERVER_IP_OR_HOST:8000/api
npm run build
```

Use the URL that **clients (browsers)** will use to reach the API (e.g. `http://192.168.1.10:8000/api` or `https://nal.example.com/api`). The built files will be in `nal/frontend/dist/`.

### 5.2 Serving the frontend

**Option A — Development server (proxy to backend)**

Good for quick testing on the same host:

```bash
cd <PROJECT_ROOT>/nal/frontend
export VITE_API_URL=http://127.0.0.1:8000/api   # or your backend URL
npm run dev
```

Then open `http://localhost:5173` (or the URL Vite prints). The dev server proxies `/api` to the backend.

**Option B — Production build + static server**

Build with the public API URL, then serve the `dist` folder with any static server (e.g. nginx, or Vite preview):

```bash
cd <PROJECT_ROOT>/nal/frontend
export VITE_API_URL=http://YOUR_SERVER:8000/api
npm run build
npm run preview
```

`npm run preview` serves `dist/` (default port 4173). For a real deployment, point nginx (or another reverse proxy) at `nal/frontend/dist` and optionally proxy `/api` to `http://127.0.0.1:8000`.

---

## 6. Quick Reference — Commands and Paths

| Step | Where | Command / Path |
|------|--------|-----------------|
| Project root | Any | Directory that **contains** `nal/` (e.g. `/opt/nal-app`) |
| DB file | Auto | `<PROJECT_ROOT>/flows.db` |
| Models | Auto | `<PROJECT_ROOT>/nal/training_pipeline/models/` |
| Backend venv | `nal/backend` | `python3 -m venv .venv && source .venv/bin/activate` |
| Backend deps | `nal/backend` | `pip install -r requirements.txt` |
| Run backend (dev) | `nal/backend` | `uvicorn app.main:app --host 0.0.0.0 --port 8000` |
| Run backend (with capture) | `nal/backend` | `sudo .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000` |
| Frontend deps | `nal/frontend` | `npm install` |
| Frontend build | `nal/frontend` | `VITE_API_URL=http://HOST:8000/api npm run build` |
| Frontend dev | `nal/frontend` | `VITE_API_URL=http://... npm run dev` |
| Frontend preview | `nal/frontend` | `npm run preview` (after build) |

---

## 7. Checklist for “Another Server”

1. **Layout:** Clone/copy so that `<PROJECT_ROOT>/nal/` exists and `<PROJECT_ROOT>` is writable.
2. **Python:** Create venv in `nal/backend`, install `requirements.txt`.
3. **Models:** Ensure `nal/training_pipeline/models/` (supervised, unsupervised, artifacts) is present; copy or train if missing.
4. **Backend:** Run from `nal/backend` with `--host 0.0.0.0`; use `sudo` if you need Active Monitoring.
5. **Frontend:** Set `VITE_API_URL` to the backend URL clients will use, then `npm run build` (or `npm run dev` for development).
6. **Ports:** Open 8000 (and 5173/4173 if serving frontend on this host).
7. **Browser:** Open the frontend URL; use the same interface (e.g. eth0) in Active Monitoring if you want to capture that network.

For model behaviour, thresholds, and Active vs Passive monitoring, see **`nal/docs/MODEL_AND_MONITORING_GUIDE.md`**.
