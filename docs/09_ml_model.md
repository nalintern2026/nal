# ML Model Details (Actual Project Behavior)

## 1) Models Used in Runtime

- **Supervised classifier:** `RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)`
- **Unsupervised detector:** `IsolationForest(n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1)`
- **Preprocessing:** `StandardScaler`
- **Label mapping:** `LabelEncoder` (for supervised class name decode)

All are loaded by `DecisionEngine` from `training_pipeline/models`.

## 2) Artifacts and Paths

- `training_pipeline/models/supervised/rf_model.pkl`
- `training_pipeline/models/unsupervised/if_model.pkl`
- `training_pipeline/models/artifacts/scaler.pkl`
- `training_pipeline/models/artifacts/label_encoder.pkl`
- `training_pipeline/models/artifacts/feature_names.pkl`
- `training_pipeline/models/metrics.json`

If any supervised artifacts are missing, the system remains operational with anomaly-only behavior.

## 3) Feature Set and Input Shape

- Feature space is CIC-style numeric flow features.
- `feature_names.pkl` is treated as source of truth.
- During inference, missing columns are auto-created as zeros before scaling.
- Current training metadata in repo indicates **79 features**.

## 4) Training Pipeline (How models are produced)

From `training_pipeline/train.py` + `core/feature_engineering.py`:

1. Collect all CSV files recursively from processed flow directories.
2. Clean rows (`replace inf`, `dropna`, normalize column names).
3. Drop non-predictive columns (IPs, ports, timestamps, IDs, etc.).
4. Separate label `Label` if present.
5. Select numeric columns and fit scaler.
6. Fit label encoder (if labels present).
7. Save scaler/encoder/feature names artifacts.
8. Split train/test (`80/20`, stratified when labels exist).
9. Train Random Forest and compute classification report.
10. Train Isolation Forest using BENIGN-only training rows when possible.
11. Persist models and metrics.

## 5) Prediction Logic (Upload and Realtime)

Both passive uploads and realtime monitoring use the same ML decision policy:

1. Input feature vector is aligned to feature names.
2. Scaler transforms features.
3. RF predicts class + probabilities (if available).
4. IF predicts anomaly flag and decision function.
5. Decision function converted to score:
   - `anomaly_score = clip(0.5 - decision_function, 0, 1)`
6. If IF says anomaly and RF label is `BENIGN`, unsupervised threat inference overrides label using flow behavior.
7. Risk score and risk level are computed.
8. Threat type, CVE refs, and textual reason are generated.

## 6) Thresholds and Risk Levels

### Risk-level thresholds (`classification_config.py`)

- `Critical`: `risk > 0.8`
- `High`: `risk > 0.6`
- `Medium`: `risk > 0.3`
- `Low`: otherwise

### Risk score formulas

- **Benign and anomalous:** `risk = anomaly_score * 0.6`
- **Threat from supervised path:** `risk = (confidence * 0.7) + (anomaly_score * 0.3)`
- **Threat when supervised unavailable:** `risk = (pseudo_conf * 0.6) + (anomaly_score * 0.4) + 0.15`

## 7) Unsupervised Threat-Type Inference Rules

Used when anomaly exists but supervised says BENIGN:

- `PortScan`: very low packet count + probe-like flags/timing.
- `Brute Force`: common auth/service ports (`21,22,23,3389,445`) + TCP profile.
- `DDoS`: very high packet/byte rates or high-volume short-duration bursts.
- `Web Attack`: traffic around web ports (`80/443`) with meaningful payload.
- `Heartbleed`: specific 443 + packet pattern heuristics.
- `Bot`: high-rate/UDP-heavy patterns (with guardrails around common web ports).
- `Infiltration`: unusual source/destination port pair + suspicious activity shape.
- Fallback to score-based `DDoS`/`Bot`/`Anomaly`.

## 8) What the Model Output Looks Like Per Flow

Each flow inserted in DB contains:

- `classification`
- `threat_type`
- `cve_refs`
- `classification_reason`
- `confidence`
- `anomaly_score`
- `risk_score`
- `risk_level`
- `is_anomaly`

## 9) Current Repo Metrics Status

- Current `training_pipeline/models/metrics.json` has `training_info` but empty `models`.
- Backend API falls back to runtime flow-derived metrics when model-metric blocks are missing.

## 10) Practical Limitations

- Heuristic threat override can mislabel edge cases in unknown traffic profiles.
- Model quality is highly dependent on label quality and dataset drift.
- If scaler/features mismatch with incoming schema, predictions degrade.
- After retraining, backend restart is recommended for deterministic artifact reload.
