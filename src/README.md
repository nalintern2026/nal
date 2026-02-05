## Module Responsibilities
- `data_collection/`: utilities to fetch/ingest datasets and manage metadata.
- `preprocessing/`: flow parsing, cleaning, validation, and basic quality checks.
- `feature_engineering/`: feature construction, scaling, encoding.
- `models/supervised/`: wrappers for classifiers (RF, XGBoost, etc.).
- `models/unsupervised/`: wrappers for detectors (Isolation Forest, autoencoders).
- `decision_engine/`: hybrid logic combining supervised confidence and anomaly scores.
- `pipelines/`: orchestrated steps for training/inference (CLI-ready).
- `evaluation/`: metrics, cross-validation, confusion matrices, ROC/PR utilities.
- `visualization/`: plotting helpers for distributions, timelines, and feature importance.
- `config/` and `utils/`: shared configs, logging, IO helpers.

## Suggested Entry Points
- `pipelines/train_supervised.py`: train/evaluate known-class models and save artifacts.
- `pipelines/train_unsupervised.py`: fit anomaly detectors and export thresholds.
- `pipelines/run_inference.py`: batch inference combining decision engine outputs.

*(Pipeline scripts are placeholders to be implemented.)*