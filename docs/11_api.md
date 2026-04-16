# API Reference

Base URL (local): `http://127.0.0.1:8000/api` (equivalent to `http://localhost:8000/api`)

## Health and System

- `GET /health`
  - **Response:** status, timestamp, model/service states.
- `GET /` (root, outside `/api`)
  - **Response:** API metadata (`message`, `docs`, `version`).

## Dashboard and Analytics

- `GET /dashboard/stats?monitor_type={passive|active}`
  - **Response:** totals, anomaly/risk distributions, timeline, top IPs/protocols.

- `GET /traffic/flows`
  - **Query params:** `page`, `per_page`, `classification`, `risk_level`, `threat_type`, `src_ip`, `protocol`, `monitor_type`.
  - **Response:** paginated flow list + totals.

- `GET /traffic/trends`
  - **Query params:** similar filters + `points`.
  - **Response:** aggregated trend points (rates, risk, confidence).

- `GET /anomalies`
  - **Query params:** pagination and filters.
  - **Response:** threat-focused list, score distribution, attack breakdown.

## Upload and History

- `POST /upload` (multipart form-data, field: `file`)
  - **Accepted:** `.pcap`, `.pcapng`, `.csv` (plus magic-byte detection for extension-less pcap/pcapng).
  - **Response:** analysis id, summary metrics, sample flows, report details.

- `GET /upload/{analysis_id}/flows`
  - **Response:** paginated flows for one upload analysis.

- `GET /history?limit=100&monitor_type={passive|active}`
  - **Response:** analysis history entries.

- `GET /history/{analysis_id}`
  - **Response:** complete report metadata + associated flows.

## Realtime Monitoring

- `POST /realtime/start?interface=<name>`
- `POST /realtime/stop`
- `GET /realtime/status`
- `GET /realtime/interfaces`
- `GET /threat-feeds/status`

## OSINT Validation

- `GET /osint/flows`
  - **Query params:** `page`, `per_page`, `src_ip`, `monitor_type`.
  - **Response:** paginated flow list where OSINT enrichment is present.

## Model and Classification Metadata

- `GET /models/metrics`
  - **Response:** training/runtime metrics, model load status.

- `GET /classification/criteria`
  - **Response:** risk thresholds, anomaly-label strategy summary, threat-to-CVE mappings.

## SBOM Security

- `POST /security/sbom/analyze` (multipart form-data, field: `file`)
- `GET /security/sbom`
- `GET /security/vulnerabilities`
- `GET /security/sbom/download`

## Example Payloads

### Upload request (curl)

```bash
curl -X POST -F "file=@capture.pcap" http://127.0.0.1:8000/api/upload
```

### Upload response shape (abbreviated)

```json
{
  "status": "success",
  "id": "a1b2c3d4",
  "filename": "capture.pcap",
  "total_flows": 1234,
  "anomaly_count": 120,
  "avg_risk_score": 0.41,
  "attack_distribution": {},
  "risk_distribution": {},
  "sample_flows": []
}
```
