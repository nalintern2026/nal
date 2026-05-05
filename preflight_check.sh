#!/usr/bin/env bash
set -u

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT" || exit 1

if [ -f ".env" ]; then
  set -a
  # shellcheck disable=SC1091
  . ".env"
  set +a
fi

print_section() {
  echo
  echo "== $1 =="
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "[PASS] $1"
}

warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  echo "[WARN] $1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "[FAIL] $1"
}

exists_cmd() {
  command -v "$1" >/dev/null 2>&1
}

check_file() {
  local path="$1"
  local label="$2"
  if [ -f "$path" ]; then
    pass "$label exists at $path"
  else
    fail "$label missing at $path"
  fi
}

print_section "Environment"
if [ -f ".env" ]; then
  pass ".env file present"
else
  warn ".env file not present (copy from .env.example)"
fi

if [ "${NETGUARD_API_KEY:-}" = "" ] || [ "${NETGUARD_API_KEY:-}" = "change-me" ]; then
  fail "NETGUARD_API_KEY is unset or default"
else
  pass "NETGUARD_API_KEY is configured"
fi

if [ "${CORS_ALLOWED_ORIGINS:-}" = "" ]; then
  warn "CORS_ALLOWED_ORIGINS is not set"
else
  pass "CORS_ALLOWED_ORIGINS is configured"
fi

DATA_ROOT="${NETGUARD_DATA_DIR:-$PROJECT_ROOT/..}"
print_section "Data paths"
echo "Using data root: $DATA_ROOT"

if [ -d "$DATA_ROOT" ]; then
  pass "Data root directory exists"
else
  fail "Data root directory does not exist"
fi

if [ -f "$DATA_ROOT/flows.db" ]; then
  pass "flows.db exists"
else
  warn "flows.db missing (it will be created at runtime if writable)"
fi

if [ -f "$DATA_ROOT/passive_timeline.db" ]; then
  pass "passive_timeline.db exists"
else
  warn "passive_timeline.db missing (it will be created at runtime if writable)"
fi

if [ -d "$DATA_ROOT/temp_uploads" ]; then
  pass "temp_uploads directory exists"
else
  warn "temp_uploads directory missing (create for uploads)"
fi

if [ -w "$DATA_ROOT" ]; then
  pass "Data root is writable"
else
  fail "Data root is not writable"
fi

print_section "Toolchain"
if exists_cmd python3; then
  pass "python3 is installed"
else
  fail "python3 is not installed"
fi

if exists_cmd npm; then
  pass "npm is installed"
else
  fail "npm is not installed"
fi

if exists_cmd docker; then
  pass "docker is installed"
else
  warn "docker is not installed (skip if not using containers)"
fi

if exists_cmd cicflowmeter; then
  pass "cicflowmeter is installed"
else
  warn "cicflowmeter is not installed (needed for PCAP to flow conversion)"
fi

print_section "Python environment"
if [ -x ".venv/bin/python" ]; then
  pass "project virtualenv detected at .venv"
else
  fail ".venv missing or python executable not found"
fi

if [ -x ".venv/bin/python" ]; then
  if .venv/bin/python - <<'PY' >/dev/null 2>&1
import importlib
mods = ["fastapi", "uvicorn", "sklearn", "pandas", "numpy"]
for m in mods:
    importlib.import_module(m)
print("ok")
PY
  then
    pass "required Python modules import successfully in .venv"
  else
    fail "required Python modules are missing in .venv"
  fi
fi

print_section "Frontend dependencies"
if [ -d "frontend/node_modules" ]; then
  pass "frontend/node_modules present"
else
  warn "frontend/node_modules missing (run npm install in frontend)"
fi

print_section "Model artifacts"
check_file "training_pipeline/models/supervised/rf_model.pkl" "Random Forest model"
check_file "training_pipeline/models/unsupervised/if_model.pkl" "Isolation Forest model"
check_file "training_pipeline/models/artifacts/scaler.pkl" "Scaler artifact"
check_file "training_pipeline/models/artifacts/label_encoder.pkl" "Label encoder artifact"
check_file "training_pipeline/models/artifacts/feature_names.pkl" "Feature names artifact"

if [ -x ".venv/bin/python" ]; then
  if .venv/bin/python - <<'PY' >/dev/null 2>&1
import pickle
from pathlib import Path
base = Path("training_pipeline/models")
paths = [
    base / "supervised" / "rf_model.pkl",
    base / "unsupervised" / "if_model.pkl",
    base / "artifacts" / "scaler.pkl",
    base / "artifacts" / "label_encoder.pkl",
    base / "artifacts" / "feature_names.pkl",
]
for p in paths:
    with open(p, "rb") as f:
        pickle.load(f)
print("ok")
PY
  then
    pass "model artifacts deserialize successfully"
  else
    fail "one or more model artifacts failed to deserialize"
  fi
fi

print_section "Backend smoke test"
if [ -x ".venv/bin/python" ]; then
  if .venv/bin/python - <<'PY' >/dev/null 2>&1
import sys
sys.path.append("backend")
import app.main
print("backend_import_ok")
PY
  then
    pass "backend import smoke test passed"
  else
    fail "backend import smoke test failed"
  fi
fi

print_section "Docker compose (optional)"
if exists_cmd docker && docker compose version >/dev/null 2>&1; then
  if docker compose config >/dev/null 2>&1; then
    pass "docker compose config is valid"
  else
    fail "docker compose config is invalid"
  fi
else
  warn "docker compose not available; skipping compose validation"
fi

echo
echo "==== Preflight summary ===="
echo "PASS: $PASS_COUNT"
echo "WARN: $WARN_COUNT"
echo "FAIL: $FAIL_COUNT"
echo

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "Result: NOT READY - fix FAIL items first."
  exit 1
fi

if [ "$WARN_COUNT" -gt 0 ]; then
  echo "Result: READY WITH WARNINGS - deployment is possible but review WARN items."
  exit 0
fi

echo "Result: READY - all checks passed."
exit 0
