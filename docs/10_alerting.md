# Alerting and Automation

## Alerting Surfaces

- Backend APIs provide monitored signals (health, stats, anomalies, realtime status).
- External alerting/orchestration is intentionally decoupled from this repository.

## Core Alert Conditions (for external integrations)

- API health is not `healthy`.
- Anomaly rate above configured threshold.
- Average risk score above configured threshold.
- Critical risk flow count above configured threshold.

## Integration Guidance

- Poll `GET /api/health`, `GET /api/dashboard/stats`, and `GET /api/anomalies`.
- Use `GET /api/model/integrity` and `GET /api/integrity` to gate alert trust.

## Integrations

- Integrate with your own webhook/email/PagerDuty stack outside this repository.

## Failure Handling

- Health-check failures should trigger API-down alerts in your orchestration layer.
- Keep threshold logic and alert noise-control in external policy code.

## Operational Notes

- This repository no longer ships workflow automation assets.
