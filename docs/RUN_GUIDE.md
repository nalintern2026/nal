# 🚀 How to Run on Another System

Use Docker for the easiest setup.

## 1. Prerequisites
- [Docker](https://docs.docker.com/get-docker/) installed.
- [Git](https://git-scm.com/downloads) installed.

## 2. Clone the Repository
Open a terminal and run:

```bash
git clone https://github.com/nalintern2026/network_security_pipeline.git
cd network_security_pipeline
```
*(Note: If the folder name is different, cd into it)*

## 3. Transfer Data & Models (Important!)
The `data/` and `models/` folders are ignored by git to keep the repo small. You must manually copy them from your original system to the new system in these locations:

- `nal/training_pipeline/data/`
- `nal/training_pipeline/models/`

## 4. Run with Docker
Start the entire system (Frontend + Backend):

```bash
cd nal
docker compose up --build
```
- Access Dashboard: [http://localhost:5173](http://localhost:5173)
- Access API Docs: [http://localhost:8000/docs](http://localhost:8000/docs)

## 5. Stop the System
Press `Ctrl+C` in the terminal, or run:
```bash
docker compose down
```

---

## Alternative: Manual Setup (No Docker)

### Backend
1. Python 3.12+ required.
2. `cd nal`
3. `python3 -m venv .venv`
4. `source .venv/bin/activate` (Linux/Mac) or `.venv\Scripts\activate` (Windows)
5. `pip install -r requirements.txt`
6. `uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload`
or from root 
`cd nal/backend && sudo .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000`

### Frontend
1. Node.js 20+ required.
2. `cd nal/frontend`
3. `npm install`
4. `npm run dev`


cd nal/backend

source .venv/bin/activate

uvicorn app.main:app --reload

can you parse through datasets and tell which are the high or critical risk data? in the path i tell you? just return few file names and its path thats all 
this is the path for the data nal/training_pipeline/data/processed/cic_ids/flows