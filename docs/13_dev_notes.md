# Developer Notes

## Design Decisions

- **Single backend API hub:** all UI and automation integrations consume one FastAPI surface.
- **Shared inference path:** passive and active modes converge on common classification/risk logic.
- **SQLite persistence:** chosen for portability and simple deployment footprint.
- **Chunked upload processing:** improves resilience for large CSV/PCAP-converted inputs.
- **Heuristic enrichment layer:** CVE mapping and reason strings improve analyst interpretability.

## Assumptions

- Most operational use is local/lab scale with single-node deployment.
- Training data follows CIC-like schema expected by feature alignment logic.
- Live capture permissions are handled by process elevation when needed.
- Webhook destination management is delegated to n8n workflow configuration.

## Trade-offs

- **Pros:** low setup complexity, quick iteration, understandable end-to-end flow.
- **Cons:** SQLite concurrency/scaling limits for larger multi-user deployments.
- **Pros:** unsupervised fallback keeps system functional without full supervised artifacts.
- **Cons:** fallback can reduce classification fidelity and produce generic labels.
- **Pros:** n8n adds rapid automation.
- **Cons:** workflow JSON currently uses hardcoded endpoints/placeholders that require manual hardening.

## Notable Gaps / Risks

- `training_pipeline/models/metrics.json` currently lacks populated model metric blocks (`models: {}`).
- `setup_project.py` references a path/config module tree not present in this repository state (legacy/unused script risk).
- n8n workflow field expectations may drift from current backend response keys if APIs evolve.
- Root-level `flows.db` can grow significantly without retention management unless cleanup routines are scheduled.
- Root-level `passive_timeline.db` is append-oriented for passive uploads and should be monitored if retention policy is introduced.

## Recommended Future Improvements

- Add automated integration tests for critical API paths and workflow contracts.
- Add schema versioning and migration scripts for DB changes.
- Externalize n8n URLs/thresholds fully to environment variables in all workflow nodes.
- Introduce role-based auth and scoped API access for production contexts.
- Add model drift tracking and artifact version tagging in metrics payload.
