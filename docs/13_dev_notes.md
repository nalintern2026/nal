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

## Trade-offs

- **Pros:** low setup complexity, quick iteration, understandable end-to-end flow.
- **Cons:** SQLite concurrency/scaling limits for larger multi-user deployments.
- **Pros:** fail-fast model integrity prevents silent incorrect classifications.
- **Cons:** strict schema checks require model/artifact discipline.

## Notable Gaps / Risks

- `training_pipeline/models/metrics.json` currently lacks populated model metric blocks (`models: {}`).
- External automation expectations may drift from backend response keys if APIs evolve.
- Root-level `flows.db` can grow significantly without retention management unless cleanup routines are scheduled.
- Root-level `passive_timeline.db` is append-oriented for passive uploads and should be monitored if retention policy is introduced.

## Recommended Future Improvements

- Add automated integration tests for critical API paths and workflow contracts.
- Add schema versioning and migration scripts for DB changes.
- Keep integration configs (webhooks/thresholds) externalized in deployment environment.
- Keep `NETGUARD_API_KEY` rotated and managed through deployment secrets.
- Add model drift tracking and artifact version tagging in metrics payload.
