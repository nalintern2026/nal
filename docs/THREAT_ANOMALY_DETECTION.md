# Threat & Anomaly Detection — Criteria & Model Flow

This document describes how the Network Analysis Lab (NAL) detects threats and anomalies in network traffic, including all thresholds, criteria, and the end-to-end flow.

---

## 1. High-Level Flow

```
PCAP/CSV Upload → Clean Data → Extract Features → Scale (StandardScaler)
                                                          ↓
                    ┌─────────────────────────────────────┴─────────────────────────────────────┐
                    ↓                                                                             ↓
            Supervised (RF)                                                              Unsupervised (IF)
            Predict class + confidence                                                  Anomaly score + is_anomaly
                    ↓                                                                             ↓
                    └─────────────────────────────────────┬─────────────────────────────────────┘
                                                          ↓
                    If RF says BENIGN but IF says anomaly → infer_anomaly_threat_type()
                                                          ↓
                    Compute risk_score → risk_level → Output (classification, threat_type, risk_level)
```

---

## 2. Data Pipeline

### 2.1 Input

- **PCAP / PCAPNG:** Converted to CSV via `cicflowmeter`.
- **CSV:** Direct flow records (CIC-IDS / CICFlowMeter schema).

### 2.2 Preprocessing

- Replace `inf` / `-inf` with NaN.
- Drop rows with NaN.
- Strip whitespace from column names.
- Drop non-predictive columns: Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, SimillarHTTP, Inbound.

### 2.3 Features

78 numeric flow features (e.g. Flow Duration, packet counts, byte lengths, IAT stats, flag counts). IPs, ports, and protocol are used only in rule-based threat-type inference, not in the ML models.

---

## 3. Supervised Detection (Random Forest)

### 3.1 Basis

- Trained on labeled CIC-IDS-style data (BENIGN, DDoS, PortScan, Bot, Infiltration, Web Attack, Brute Force, etc.).
- Uses the same 78 numeric features after scaling.

### 3.2 Criteria

- **Threat:** Predicted class ≠ BENIGN.
- **Confidence:** `max(class_probabilities)` per flow.

### 3.3 Fallback

- If RF or label encoder is missing, all flows are labeled BENIGN and risk is computed from anomaly score only.

---

## 4. Unsupervised Detection (Isolation Forest)

### 4.1 Basis

- Trained only on BENIGN flows (or all data if no labels).
- Learns “normal” behavior; outliers are anomalies.

### 4.2 Parameters

| Parameter | Value |
|-----------|-------|
| `n_estimators` | 100 |
| `contamination` | 0.01 |
| `random_state` | 42 |

### 4.3 Criteria

- **Anomaly score:** `0.5 - decision_function(X)`, clipped to [0, 1].
- **Is anomaly:** `predict(X) == -1`.

### 4.4 Thresholds

- None explicitly defined; Isolation Forest uses `contamination` internally.

---

## 5. Risk Level

### 5.1 Thresholds

| Risk Level | Condition |
|------------|-----------|
| **Critical** | risk_score > 0.8 |
| **High** | risk_score > 0.6 |
| **Medium** | risk_score > 0.3 |
| **Low** | risk_score ≤ 0.3 |

### 5.2 Risk Formula

| Scenario | Formula |
|----------|---------|
| **BENIGN** | `risk = anomaly_score × 0.6` |
| **Supervised threat** | `risk = (confidence × 0.7) + (anomaly_score × 0.3)` |
| **Unsupervised-only threat** | `risk = (pseudo_conf × 0.6) + (anomaly_score × 0.4) + 0.15` |

Where `pseudo_conf = max(conf, min(1.0, 0.55 + (0.45 × anomaly_score)))`.

---

## 6. Unsupervised Threat-Type Inference

When the supervised model says BENIGN but IF says anomaly, the system infers a threat type from flow features and anomaly score using rules.

### 6.1 Thresholds (Score-Based Fallback)

| Label | Anomaly Score Threshold |
|-------|--------------------------|
| DDoS | > 0.8 |
| Bot | > 0.6 |
| Bot (alternative) | > 0.45 |
| Anomaly | ≤ 0.45 (default) |

### 6.2 Rule-Based Criteria (Evaluated in Order)

#### PortScan

| Condition | Threshold |
|-----------|-----------|
| Total packets | 1–6 |
| SYN flag count | ≥ 1 **or** flow duration < 3 s |

#### Brute Force

| Condition | Threshold |
|-----------|-----------|
| Protocol | TCP |
| Destination port | 21, 22, 23, 3389, 445 |
| Total packets | 2–300 |
| Duration | < 180 s or 0 |

#### DDoS

| Condition | Threshold |
|-----------|-----------|
| Flow packets/s | > 1500 |
| **or** Flow bytes/s | > 1,000,000 |
| **or** Total packets | > 500 **and** duration < 15 s |
| **or** Total bytes | > 5,000,000 **and** duration < 60 s |
| **or** Anomaly score | > 0.85 **and** (flow_pkts_s > 200 **or** tot_pkts > 100) |

#### Web Attack

| Condition | Threshold |
|-----------|-----------|
| Destination port | 80 or 443 |
| Protocol | TCP |
| Total bytes | > 20,000 |
| Total packets | ≥ 4 |

#### Heartbleed

| Condition | Threshold |
|-----------|-----------|
| Destination port | 443 |
| Total packets | 2–25 |
| Avg packet length | 50–300 bytes |

#### Bot

| Condition | Threshold |
|-----------|-----------|
| Flow packets/s | > 200 **and** total packets ≥ 8 |
| **or** Protocol | UDP **and** total packets > 20 **and** anomaly_score > 0.4 |
| **or** Anomaly score | > 0.65 **and** total packets ≥ 15 |

#### Infiltration

| Condition | Threshold |
|-----------|-----------|
| Destination port | Not in (21, 22, 23, 80, 443, 3389, 445) **and** port > 0 |
| Total packets | ≥ 4 |
| Total bytes | > 500 |

#### Score-Based Fallback (if no rule matches)

| Anomaly Score | Label |
|---------------|-------|
| > 0.8 | DDoS |
| > 0.6 | Bot |
| > 0.45 | Bot |
| 1–8 packets | PortScan |
| Else | Anomaly |

---

## 7. Threat vs. Benign (DB / UI)

A flow is treated as a **threat** if:

- `is_anomaly = 1`, **or**
- `classification != 'benign'` (case-insensitive)

---

## 8. CVE Mapping (Threat Types)

| Classification | Threat Type | CVE References |
|----------------|-------------|----------------|
| BENIGN / Benign | Normal | — |
| DDoS / DoS | Denial of Service | CVE-2020-5902, CVE-2018-1050 |
| Bot | Botnet / Malware | CVE-2016-10709, CVE-2023-44487 |
| PortScan | Reconnaissance | — |
| Brute Force / BruteForce / FTP-Patator / SSH-Patator | Brute Force | CVE-2019-11510, CVE-2017-5638 |
| Web Attack | Web Application Attack | CVE-2017-5638, CVE-2018-11776 |
| Infiltration | Infiltration | CVE-2017-0144 |
| Heartbleed | Heartbleed (TLS) | CVE-2014-0160 |
| DoS GoldenEye / DoS Hulk / DoS SlowHTTPTest | Denial of Service | CVE-2020-5902, CVE-2018-1050 |
| Anomaly | Unclassified Anomaly | — |

---

## 9. Model Artifacts

| Artifact | Path |
|----------|------|
| Supervised model | `training_pipeline/models/supervised/rf_model.pkl` |
| Unsupervised model | `training_pipeline/models/unsupervised/if_model.pkl` |
| Scaler | `training_pipeline/models/artifacts/scaler.pkl` |
| Label encoder | `training_pipeline/models/artifacts/label_encoder.pkl` |
| Feature names | `training_pipeline/models/artifacts/feature_names.pkl` |

---

---

## 11. SBOM Security (Dependency Analysis)

### 11.1 Overview

The SBOM Security module is **user-centric**: users upload their own dependency files to build a Software Bill of Materials (SBOM) and check for known vulnerabilities.

- **No static data:** The application does not use any hardcoded or pre-built SBOM or vulnerability list.
- **No project dependencies:** This project’s own dependencies (e.g. from this repo’s requirements.txt or package.json) are never scanned or shown. All data comes solely from files that **users** upload and analyze.
- Users must upload and analyze a dependency file to see any SBOM or vulnerability results.

### 11.2 Supported Files

| File Type | Ecosystem | Parser |
|-----------|-----------|--------|
| requirements.txt | PyPI | Line-based (package==version) |
| package.json | npm | JSON (dependencies, devDependencies, peerDependencies) |
| package-lock.json | npm | Lockfile packages (exact versions) |
| yarn.lock | npm | Lockfile package@version blocks |
| Pipfile | PyPI | [packages] section |
| poetry.lock | PyPI | [[package]] sections |
| Gemfile | RubyGems | gem lines |
| Gemfile.lock | RubyGems | GEM section |
| go.mod | Go | require block |
| Cargo.toml | crates.io | [dependencies] section |
| Cargo.lock | crates.io | [[package]] sections |

### 11.3 Flow

```
User uploads file → Parse dependencies → For each package: query OSV API (with pagination)
                                                          ↓
                    Build SBOM components + vulnerability list (severity, fixed_in, CVSS when available)
                                                          ↓
                    Attach remediation tips per vulnerability → Return to UI
```

### 11.4 Severity Thresholds

| Severity | CVSS Score | Action Priority |
|----------|------------|-----------------|
| **Critical** | 9.0–10.0 | Update immediately |
| **High** | 7.0–8.9 | Update within 24–48 hours |
| **Medium** | 4.0–6.9 | Schedule in next sprint |
| **Low** | 0.1–3.9 | Include in regular updates |

Severity is derived from OSV data: CVSS score (when present) or ecosystem/database severity field.

### 11.5 Remediation Tips (User Guidance)

**By Severity:**

- **Critical:** Update immediately; test in staging first; consider temporary mitigations; notify security team.
- **High:** Plan update within 24–48 hours; check CVE for workarounds; run security scans in CI/CD; assess exploitability.
- **Medium:** Schedule update; assess exploitability; pin fixed versions in lock file; add tracking ticket.
- **Low:** Include in regular dependency update cycles; document for maintenance.

**By Vulnerability Type:**

- **XSS:** Sanitize user input; use Content-Security-Policy headers.
- **Injection:** Use parameterized queries and input validation.
- **RCE:** Restrict network access; run with least privilege.
- **DoS:** Implement rate limiting and resource caps.
- **SSRF:** Validate and restrict outbound URLs.
- **Auth:** Use strong authentication and session management.
- **Path traversal:** Validate and sanitize file paths.
- **Prototype pollution:** Avoid merging user objects; use safe defaults.
- **Memory issues:** Ensure proper bounds checking; upgrade to patched version.
- **Bypass:** Implement defense in depth; validate all security checks.

**General:**

- Run `pip install package==fixed_version` (PyPI) or `npm install package@fixed_version` (npm).
- Check NVD/CVE or GitHub Advisory for full details and exploitability.
- Pin dependencies to fixed versions in lock files after updating.

### 11.6 Data Source

- **OSV API:** https://api.osv.dev/v1/query — no API key required; aggregates GitHub Security Advisories, PyPA, NVD, RustSec, and other sources. Pagination is supported for packages with many vulnerabilities.

### 11.7 Advisory Links

- **CVE:** https://nvd.nist.gov/vuln/detail/{id}
- **GHSA:** https://github.com/advisories/{id}
- **Other:** First reference URL or https://osv.dev/vulnerability/{id}

### 11.8 SBOM End-to-End Flow

1. **Upload:** User uploads requirements.txt, package.json, package-lock.json, yarn.lock, Pipfile, poetry.lock, Gemfile, Gemfile.lock, go.mod, Cargo.toml, or Cargo.lock.
2. **Parse:** Extract package name and version per ecosystem.
3. **Query:** For each package, call OSV API for vulnerabilities (supports pagination).
4. **Enrich:** Attach severity (CVSS when available), fixed_in, and remediation tips per vulnerability.
5. **Output:** SBOM components + vulnerabilities with tips for UI. Each vulnerability includes a link to the advisory (NVD, GitHub, or OSV).

---

## 12. End-to-End Working (Network Traffic)

1. **Upload:** User uploads PCAP or CSV.
2. **Convert:** PCAP → CSV via cicflowmeter (if needed).
3. **Clean:** Drop NaN/inf, align columns.
4. **Scale:** Apply saved StandardScaler to numeric features.
5. **Supervised:** RF predicts class and confidence.
6. **Unsupervised:** IF computes anomaly score and `is_anomaly`.
7. **Override:** If RF = BENIGN and IF = anomaly → `infer_anomaly_threat_type()` assigns threat type.
8. **Risk:** Compute risk_score and risk_level.
9. **Output:** Per-flow classification, threat_type, risk_level, anomaly_score, confidence, and human-readable reason.

### 11.7 SBOM End-to-End Flow

1. **Upload:** User uploads requirements.txt, package.json, or other dependency file.
2. **Parse:** Extract package name and version per ecosystem.
3. **Query:** For each package, call OSV API for vulnerabilities.
4. **Enrich:** Attach severity, fixed_in, and remediation tips per vulnerability.
5. **Output:** SBOM components + vulnerabilities with tips for UI.
