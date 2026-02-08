## Data Layout
- `raw/`: original PCAPs or vendor-provided flow exports (read-only).
- `external/`: third-party benchmark datasets (e.g., CIC-IDS, UNSW-NB15).
- `interim/flows/`: initial flow exports before validation/cleaning.
- `interim/cleaned_flows/`: cleaned/validated flow CSVs.
- `processed/feature_vectors/`: engineered numeric feature tables ready for modeling.
- `processed/encoders/` and `processed/scalers/`: fitted preprocessing objects.
- `processed/model_inputs/`: train/val/test splits or folds.
- `processed/anomaly_scores/`: scored flows and thresholds for review.

## Conventions
- Treat `raw/` as immutable; regenerate downstream data via scripts/notebooks.
- Name files with dataset + stage + timestamp (e.g., `bsnl_flows_2026-02-05.csv`).
- Include a brief dataset note in `docs/dataset_notes.md` for each new drop.