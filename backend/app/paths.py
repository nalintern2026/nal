from __future__ import annotations

import os
from pathlib import Path


APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent
WORKSPACE_ROOT = PROJECT_ROOT.parent


def _data_root() -> Path:
    configured = os.environ.get("NETGUARD_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return WORKSPACE_ROOT


DATA_ROOT = _data_root()
DB_PATH = DATA_ROOT / "flows.db"
PASSIVE_TIMELINE_DB_PATH = DATA_ROOT / "passive_timeline.db"
TEMP_UPLOADS_DIR = DATA_ROOT / "temp_uploads"

MODELS_DIR = PROJECT_ROOT / "training_pipeline" / "models"
SUPERVISED_MODEL_PATH = MODELS_DIR / "supervised" / "rf_model.pkl"
UNSUPERVISED_MODEL_PATH = MODELS_DIR / "unsupervised" / "if_model.pkl"
ARTIFACTS_DIR = MODELS_DIR / "artifacts"
SCALER_PATH = ARTIFACTS_DIR / "scaler.pkl"
LABEL_ENCODER_PATH = ARTIFACTS_DIR / "label_encoder.pkl"
FEATURE_NAMES_PATH = ARTIFACTS_DIR / "feature_names.pkl"
