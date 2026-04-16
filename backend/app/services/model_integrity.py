from __future__ import annotations

import pickle
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.paths import (
    SUPERVISED_MODEL_PATH,
    UNSUPERVISED_MODEL_PATH,
    SCALER_PATH,
    LABEL_ENCODER_PATH,
    FEATURE_NAMES_PATH,
)


@dataclass
class CheckResult:
    name: str
    status: str
    details: str


def _ok(name: str, details: str) -> CheckResult:
    return CheckResult(name=name, status="ok", details=details)


def _fail(name: str, details: str) -> CheckResult:
    return CheckResult(name=name, status="failed", details=details)


def _load_pickle(path) -> Any:
    with open(path, "rb") as fh:
        return pickle.load(fh)


def evaluate_model_integrity() -> dict[str, Any]:
    checks: list[CheckResult] = []

    required = [
        ("rf_model", SUPERVISED_MODEL_PATH),
        ("if_model", UNSUPERVISED_MODEL_PATH),
        ("scaler", SCALER_PATH),
        ("label_encoder", LABEL_ENCODER_PATH),
        ("feature_names", FEATURE_NAMES_PATH),
    ]
    for name, path in required:
        if path.exists():
            checks.append(_ok(f"{name}_exists", str(path)))
        else:
            checks.append(_fail(f"{name}_exists", f"Missing artifact: {path}"))

    rf = if_model = scaler = label_encoder = feature_names = None
    if SUPERVISED_MODEL_PATH.exists():
        try:
            rf = _load_pickle(SUPERVISED_MODEL_PATH)
            checks.append(_ok("rf_loadable", rf.__class__.__name__))
        except Exception as e:
            checks.append(_fail("rf_loadable", str(e)))
    if UNSUPERVISED_MODEL_PATH.exists():
        try:
            if_model = _load_pickle(UNSUPERVISED_MODEL_PATH)
            checks.append(_ok("if_loadable", if_model.__class__.__name__))
        except Exception as e:
            checks.append(_fail("if_loadable", str(e)))
    if SCALER_PATH.exists():
        try:
            scaler = _load_pickle(SCALER_PATH)
            checks.append(_ok("scaler_loadable", scaler.__class__.__name__))
        except Exception as e:
            checks.append(_fail("scaler_loadable", str(e)))
    if LABEL_ENCODER_PATH.exists():
        try:
            label_encoder = _load_pickle(LABEL_ENCODER_PATH)
            class_count = len(getattr(label_encoder, "classes_", []))
            checks.append(_ok("label_encoder_loadable", f"classes={class_count}"))
        except Exception as e:
            checks.append(_fail("label_encoder_loadable", str(e)))
    if FEATURE_NAMES_PATH.exists():
        try:
            feature_names = _load_pickle(FEATURE_NAMES_PATH)
            if not isinstance(feature_names, (list, tuple)) or not feature_names:
                checks.append(_fail("feature_names_valid", "feature_names.pkl must contain a non-empty list/tuple"))
            else:
                checks.append(_ok("feature_names_valid", f"count={len(feature_names)}"))
        except Exception as e:
            checks.append(_fail("feature_names_valid", str(e)))

    # Compatibility checks
    if rf is not None and feature_names is not None:
        n_in = getattr(rf, "n_features_in_", None)
        if n_in is not None and int(n_in) != len(feature_names):
            checks.append(_fail("rf_feature_compatibility", f"RF expects {n_in} features, feature_names has {len(feature_names)}"))
        else:
            checks.append(_ok("rf_feature_compatibility", "compatible"))

    if if_model is not None and feature_names is not None:
        n_in = getattr(if_model, "n_features_in_", None)
        if n_in is not None and int(n_in) != len(feature_names):
            checks.append(_fail("if_feature_compatibility", f"IF expects {n_in} features, feature_names has {len(feature_names)}"))
        else:
            checks.append(_ok("if_feature_compatibility", "compatible"))

    if scaler is not None and feature_names is not None:
        n_in = getattr(scaler, "n_features_in_", None)
        if n_in is not None and int(n_in) != len(feature_names):
            checks.append(_fail("scaler_feature_compatibility", f"Scaler expects {n_in} features, feature_names has {len(feature_names)}"))
        else:
            checks.append(_ok("scaler_feature_compatibility", "compatible"))

    if label_encoder is not None:
        classes = getattr(label_encoder, "classes_", None)
        if classes is None or len(classes) == 0:
            checks.append(_fail("label_encoder_classes", "Label encoder has no classes_"))
        else:
            checks.append(_ok("label_encoder_classes", f"{len(classes)} classes"))

    failed = [c for c in checks if c.status == "failed"]
    return {
        "status": "failed" if failed else "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": [c.__dict__ for c in checks],
    }
