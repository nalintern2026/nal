# Troubleshooting Guide

## Common Issues and Fixes

## 1) Backend Not Reachable

- **Symptoms:** frontend shows API offline, `curl /api/health` fails.
- **Checks:**
  - backend process is running on port 8000,
  - CORS/API base URL alignment.
- **Fix:** restart backend with correct host/port.

## 2) Upload Fails with Unsupported File Type

- **Symptoms:** `400 File type not supported`.
- **Fix:** use `.pcap`, `.pcapng`, or `.csv`; ensure file is not corrupted.

## 3) PCAP Conversion Errors

- **Symptoms:** upload returns server error during conversion.
- **Likely cause:** `cicflowmeter` missing from venv path.
- **Fix:** reinstall dependencies in backend venv and verify CICFlowMeter binary availability.

## 4) Live Monitoring Captures No Data

- **Symptoms:** monitor running but active flow count remains zero.
- **Checks:**
  - backend started with `sudo`,
  - correct interface selected,
  - traffic actually present on selected interface.
- **Fix:** use loopback (`lo`) and generate local traffic first; then test other interfaces.

## 5) Models Not Loaded

- **Symptoms:** `/api/health` shows supervised/anomaly inactive, low-confidence behavior.
- **Cause:** missing artifacts in `training_pipeline/models`.
- **Fix:** run training pipeline and restart backend.

## 6) SBOM Scan Returns Empty/Warnings

- **Symptoms:** zero components, warnings about unknown versions.
- **Cause:** unsupported/irregular dependency file format or unpinned versions.
- **Fix:** upload supported manifest with explicit versions.

## 7) External Alerts Not Delivered

- **Symptoms:** external integration executes but no notification.
- **Cause:** webhook URL/credential issues in your orchestration platform.
- **Fix:** validate webhook endpoint independently and re-run with backend health/integrity checks first.

## Logs and Signal Interpretation

- Backend logs are primary source for conversion/inference/runtime thread errors.
- Realtime status endpoint includes `capture_error`; inspect this first for permission/interface issues.
- DB-backed APIs (`/dashboard/stats`, `/history`) validate whether inference outputs are actually being persisted.

## Quick Debug Sequence

1. `GET /api/health`
2. upload one known-good CSV
3. `GET /api/dashboard/stats`
4. verify history entry
5. start realtime and check `/api/realtime/status`
6. inspect frontend pages after each step
