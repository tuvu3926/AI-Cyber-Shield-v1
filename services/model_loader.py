"""Model loading and validation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib

from services.feature_extractor import FEATURE_NAMES


@dataclass(frozen=True)
class LoadedModels:
    random_forest: Any
    naive_bayes: Any
    feature_columns: list[str]
    naive_bayes_scaler: Any | None = None


def load_models(random_forest_path: Path, naive_bayes_path: Path) -> LoadedModels:
    rf_model, rf_columns, _rf_scaler = _load_model_bundle(random_forest_path)
    nb_model, nb_columns, nb_scaler = _load_model_bundle(naive_bayes_path)
    if rf_columns != nb_columns:
        raise RuntimeError("Random Forest and Naive Bayes feature columns differ.")

    return LoadedModels(
        random_forest=rf_model,
        naive_bayes=nb_model,
        feature_columns=rf_columns,
        naive_bayes_scaler=nb_scaler,
    )


def _load_model_bundle(path: Path) -> tuple[Any, list[str], Any | None]:
    if not Path(path).exists():
        raise FileNotFoundError(f"Model file not found: {path}")
    data = joblib.load(path)
    scaler = None
    if isinstance(data, dict) and "model" in data and "feature_columns" in data:
        model = data["model"]
        feature_columns = list(data["feature_columns"])
        scaler = data.get("scaler")
    else:
        model = data
        feature_columns = list(getattr(model, "feature_names_in_", []))
        if not feature_columns and hasattr(model, "n_features_in_"):
            feature_count = int(model.n_features_in_)
            if feature_count == len(FEATURE_NAMES):
                feature_columns = list(FEATURE_NAMES)
        if not feature_columns:
            raise RuntimeError(f"Invalid model bundle: {path}")
    if not hasattr(model, "predict_proba") or not hasattr(model, "classes_"):
        raise RuntimeError(f"Model does not support probability inference: {path}")
    return model, feature_columns, scaler
