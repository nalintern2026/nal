# Network Traffic Classification and Anomaly Detection

Adaptive flow-level ML framework for supervised traffic classification, unsupervised anomaly detection, and a hybrid decision engine aligned with ITC/NAL operational traffic.

## Repository Structure (scaffolded)
- `data/`
  - `raw/` — incoming PCAPs or exported flows (read-only)
  - `external/` — third-party datasets (e.g., CIC-IDS, UNSW-NB15)
  - `interim/flows/` — raw flow exports before cleaning
  - `interim/cleaned_flows/` — validated/cleaned flow CSVs
  - `processed/feature_vectors/` — engineered numeric features
  - `processed/encoders/`, `processed/scalers/` — fitted transformers
  - `processed/anomaly_scores/` — scored flows for review
  - `processed/model_inputs/` — train/val/test splits
- `src/`
  - `data_collection/` — dataset ingestion helpers
  - `preprocessing/` — flow parsing, cleaning, validation
  - `feature_engineering/` — feature builders and encoders
  - `models/supervised/` and `models/unsupervised/` — ML model wrappers
  - `decision_engine/` — hybrid decision logic
  - `pipelines/` — end-to-end orchestrations/entrypoints
  - `evaluation/` — metrics, cross-validation, reports
  - `visualization/` — plotting utilities
  - `config/`, `utils/` — shared config and helpers
- `configs/` — experiment or pipeline config files (YAML/JSON)
- `pipelines/` — CLI entry scripts for batch runs
- `scripts/` — one-off utilities (e.g., data sanity checks)
- `artifacts/` — trained models and encoders
- `notebooks/`
  - `exploratory/` — dataset profiling and sanity checks
  - `model_dev/` — model prototyping
  - `reports/` — static analysis notebooks for sharing
- `results/`
  - `figures/`, `metrics/`, `reports/` — outputs for review
- `docs/` — dataset notes, experiment logs, feature descriptions

## Phase Mapping
- Phase 1–2: ingest PCAPs into `data/raw` → flows in `data/interim/flows` → cleaned `data/interim/cleaned_flows`.
- Phase 3: feature extraction to `data/processed/feature_vectors` plus fitted encoders/scalers.
- Phase 4: supervised models saved under `artifacts/models/supervised`.
- Phase 5: unsupervised detectors saved under `artifacts/models/unsupervised`; anomaly scores in `data/processed/anomaly_scores`.
- Phase 6: hybrid decisions implemented in `src/decision_engine`; outputs archived in `results/`.
- Phase 7–8: visualization and reporting under `results/` with documentation in `docs/`.

## Usage Notes
- Keep `data/raw` immutable; derive all downstream data via scripts/notebooks.
- Track dataset provenance and assumptions in `docs/dataset_notes.md`.
- Log experiments (configs, seeds, metrics) in `docs/experiment_log.md`.
- Document feature definitions and encoding choices in `docs/feature_description.md`.


ictd@ICTD:~/Desktop/Network$ tree -L 6
.
└── nal
    ├── configs
    │   └── system_config.template.yaml
    ├── data
    │   ├── processed
    │   │   ├── bsnl
    │   │   └── cic_ids
    │   │       ├── cleaned
    │   │       ├── features
    │   │       └── flows
    │   │           ├── friday
    │   │           ├── monday
    │   │           ├── thursday
    │   │           ├── tuesday
    │   │           └── wednesday
    │   ├── raw
    │   │   ├── bsnl
    │   │   │   └── raw_flows
    │   │   ├── cic_ids
    │   │   │   ├── metadata
    │   │   │   ├── pcap
    │   │   │   │   ├── Friday-WorkingHours.pcap
    │   │   │   │   ├── Monday-WorkingHours.pcap
    │   │   │   │   ├── Thursday-WorkingHours.pcap
    │   │   │   │   ├── Tuesday-WorkingHours.pcap
    │   │   │   │   └── Wednesday-workingHours.pcap
    │   │   │   └── pcap_chunks
    │   │   │       ├── friday
    │   │   │       ├── monday
    │   │   │       ├── thursday
    │   │   │       ├── tuesday
    │   │   │       └── wednesday
    │   │   └── unsw_nb15
    │   │       ├── csv
    │   │       └── documentation
    │   └── README.md
    ├── docs
    │   ├── dataset_notes.md
    │   ├── experiment_log.md
    │   └── feature_description.md
    ├── README.md
    ├── requirements.txt
    ├── results
    │   └── README.md
    ├── scripts
    │   ├── pcap_chunks_to_flows.py
    │   └── setup_project.py
    └── src
        ├── data_collection
        │   └── __init__.py
        ├── decision_engine
        │   └── __init__.py
        ├── feature_engineering
        │   └── __init__.py
        ├── __init__.py
        ├── models
        │   ├── __init__.py
        │   ├── supervised
        │   │   └── __init__.py
        │   └── unsupervised
        │       └── __init__.py
        ├── preprocessing
        │   └── __init__.py
        ├── README.md
        └── visualization
            └── __init__.py

42 directories, 25 files