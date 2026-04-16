# Intelligence Layers: OSINT, CVE, and SBOM

## OSINT Integration

OSINT enrichment is implemented in `backend/app/services/osint.py` and executed for anomaly-flagged flows.

### External Sources

- **AbuseIPDB** (`/api/v2/check`) -> abuse confidence score.
- **VirusTotal** (`/api/v3/ip_addresses/{ip}`) -> malicious ratio score.

### Runtime Controls

- global toggle: `OSINT_ENABLED`,
- retry count: `OSINT_MAX_RETRIES`,
- TTL cache: `OSINT_CACHE_TTL_SECONDS`,
- skip internal/reserved IPs: `OSINT_SKIP_NON_PUBLIC_IPS`,
- rate limiting per provider,
- per-process dedup of repeated IP checks.

## Threat Feed System

Local feed intelligence is managed by `backend/app/services/threat_feeds.py`:

- refreshes on startup, then periodically in background,
- tracks feed health and retains old feed data if refresh fails,
- computes `feed_score` from number of source matches.

Feed signal is included in final scoring and explanation payloads.

## CVE Mapping Logic

CVE mapping is defined in `backend/app/classification_config.py`:

- threat class -> threat type + CVE references + textual description,
- mapping is used when constructing per-flow output fields:
  - `threat_type`
  - `cve_refs`
  - `classification_reason`

Unknown/benign paths are handled explicitly (not all classes produce CVEs).

## SBOM Vulnerability Scanning

SBOM logic is implemented in `backend/app/services/sbom_service.py`, exposed through security endpoints.

### Input Scope

User-uploaded dependency manifests only (e.g., requirements, package files, lockfiles).  
The service does not scan arbitrary repository state by default.

### Processing

1. Parse dependencies by ecosystem format.
2. Build component list and CycloneDX-compatible output.
3. Query OSV for package-version vulnerability records.
4. Normalize severities and aggregate distribution.
5. Return components, vulnerabilities, warnings, and scan status per component.

## Enrichment Application Path

For anomaly flows:

1. ML layer emits class/confidence/anomaly score.
2. Threat-feed match check is always available.
3. External OSINT checks are attempted subject to controls/cache/rate limits.
4. Fused final score + verdict are computed.
5. Explanation list is attached to flow record and persisted.

## Scoring Fusion Logic

The implementation combines:

- **ML anomaly signal**
- **RF confidence**
- **feed score**
- **AbuseIPDB score (if available)**
- **VirusTotal score (if available)**

Weighted formula branches are selected based on available OSINT evidence:

- full branch (ML + feed + API OSINT),
- feed-only branch,
- ML-only branch.

Final score is bounded to `0..100` and mapped to verdict tiers:

- Verified Threat
- Suspicious
- Unconfirmed Threat
- Likely False Positive

## Explanation Generation

Explanation generation combines:

- classification reason (feature/label-level rationale),
- CVE/threat semantics,
- feed match details,
- OSINT source outcomes and score effects.

The output is persisted in flow `explanation` field and surfaced in UI/API responses.
