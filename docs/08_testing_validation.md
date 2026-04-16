# Testing and Validation

## Functional Validation Checklist

## 1) API Health

- **Test:** `GET /api/health`
- **Expected:** `status=healthy`, service states returned.
- **Failure signal:** timeout/connection error or malformed JSON.

## 2) Upload Path Validation

- **Test input:** known CSV from `training_pipeline/data/processed/...`.
- **Endpoint:** `POST /api/upload`.
- **Expected:**
  - non-zero `total_flows`,
  - `attack_distribution`, `risk_distribution` populated,
  - rows visible in `dashboard/stats` and `history`.

Convenience script:

```bash
cd /home/ictd/Desktop/Network/nal
bash test_upload.sh
```

## 3) Realtime Path Validation

- **Test:** start monitor, generate local traffic, query status.
- **Endpoints:** `/api/realtime/start`, `/api/realtime/status`, `/api/dashboard/stats?monitor_type=active`.
- **Expected:** `running=true`, increasing capture/flow counters, active rows present.

## 4) Frontend Validation

- Dashboard cards/charts update every few seconds.
- Upload page returns detailed tables.
- Anomalies and Traffic pages filter/paginate correctly.
- History report opens and shows persisted metadata + flows.
- SBOM page returns components/vulnerability details after upload.

## 5) Integrity Validation

- `GET /api/model/integrity` returns check list and status.
- `GET /api/integrity` returns overall + individual backend checks.
- Confirm critical checks are `ok` before trust in alerting/reporting.

## ML Validation Approach

- Confirm artifacts exist and load (`/api/models/metrics` model status).
- Compare `metrics.json` values after retraining.
- Run known benign-heavy and attack-heavy samples and inspect:
  - anomaly rate changes,
  - risk-level distribution shifts,
  - threat-type plausibility.

## Realistic Test Cases

1. **Benign-biased CSV** -> low anomaly rate and mostly `Low`/`Medium` risk.
2. **Attack-heavy CSV** -> elevated anomaly count and `High`/`Critical` risks.
3. **Invalid file extension** -> API returns 400 with supported-type message.
4. **Large upload** -> completes without memory exhaustion due to chunking.
5. **SBOM with unknown versions** -> scan completes with warning entries.

## Debugging Anomalies

- Check backend logs for conversion/inference exceptions.
- Query small slices from `/api/traffic/flows` and inspect `classification_reason`.
- Verify model artifacts are fresh and compatible with current feature set.
- Confirm protocol/monitor filters are set correctly when interpreting charts.
