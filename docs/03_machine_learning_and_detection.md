# Machine Learning and Detection

## Model Stack in Runtime

NetGuard uses a dual-model detection strategy:

- **Random Forest (supervised)** for class prediction and confidence.
- **Isolation Forest (unsupervised)** for anomaly intensity and anomaly flag.

Both are required for normal operation; inference paths do not silently downgrade.

## Random Forest Usage

- Trained in `training_pipeline/train.py` using `RandomForestClassifier`.
- Runtime object loaded from artifact path `models/supervised/rf_model.pkl`.
- Inference outputs:
  - predicted class label (via label encoder decode),
  - class probability vector,
  - confidence = max probability.

## Isolation Forest Usage

- Trained in `training_pipeline/train.py` using `IsolationForest`.
- Runtime artifact: `models/unsupervised/if_model.pkl`.
- Inference outputs:
  - `decision_function` value,
  - anomaly flag (`predict == -1`),
  - normalized anomaly score computed as:
    - `anomaly_score = clip(0.5 - decision_function, 0, 1)`.

## Feature Engineering (CIC-Style Flow Features)

Feature preparation is implemented in `core/feature_engineering.py`:

- cleans NaN/Inf rows,
- drops non-predictive columns (IDs, addresses, timestamps, protocol metadata),
- keeps numeric feature columns only,
- scales features using `StandardScaler`,
- encodes labels with `LabelEncoder` in training mode.

Runtime schema is strictly validated against `feature_names.pkl` before scoring.

## Training Pipeline Overview

Training path (`training_pipeline/train.py`) performs:

1. Dataset discovery over CSV and capture-file paths.
2. Optional conversion of pcap/pcapng via `cicflowmeter`.
3. Feature preprocessing and scaling.
4. Supervised RF training + metrics.
5. IF training (preferably on benign subset).
6. Artifact serialization and metrics export (`models/metrics.json`).

If labeled data is unavailable, pseudo-labeling can be used through an existing IF model.

## Inference Pipeline

Inference path is centered in `backend/app/services/decision_service.py`:

1. Input file/flow rows are cleaned and normalized.
2. Feature set is validated against model artifact schema.
3. RF + IF inference is executed.
4. Threat labels may be adjusted when IF flags anomaly but RF predicts benign.
5. Risk score and risk level are assigned.
6. CVE/threat metadata and explanation text are added.
7. Optional OSINT/feed enrichment is applied to anomalous flows.
8. Final fields are persisted and may trigger alerts.

## Fail-Fast Behavior

The runtime fails explicitly when artifacts are missing/incompatible:

- Required artifacts:
  - RF model, IF model, scaler, label encoder, feature names.
- Missing artifacts or schema mismatch produce hard errors (`MODEL_UNAVAILABLE` / schema mismatch), not fallback predictions.
- Model integrity endpoint validates artifact loadability and feature compatibility.

## Model Artifact Structure

Expected artifact files:

- `models/supervised/rf_model.pkl`
- `models/unsupervised/if_model.pkl`
- `models/artifacts/scaler.pkl`
- `models/artifacts/label_encoder.pkl`
- `models/artifacts/feature_names.pkl`
- `models/metrics.json` (training/evaluation metadata)

## Model Versioning in Runtime

Model lifecycle is persisted in `model_versions`:

- startup registers a derived version string (`rf:<bool>-if:<bool>-features:<n>`),
- previous active version is deactivated,
- current version is marked active,
- each persisted flow stores `model_version`.

## Current ML Limitations

- No online/reinforcement retraining loop in runtime service.
- Behavior depends on strict schema compatibility with artifact feature names.
- Some data paths rely on external flow conversion (`cicflowmeter`) for pcap inputs.
- Risk/verdict logic uses rule + score fusion; calibration is static unless retrained/reconfigured.
