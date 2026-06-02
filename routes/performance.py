"""Model performance and metadata API routes."""

from __future__ import annotations

import csv
from pathlib import Path

from flask import Blueprint, current_app, jsonify, send_file, url_for

from services.feature_extractor import FEATURE_NAMES
from services.detector import FEATURE_ALIASES


performance_bp = Blueprint("performance", __name__, url_prefix="/api")

REPORT_IMAGES = {
    "rf_confusion_matrix": ("ma_tran_nham_lan_rf.png", "Random Forest Confusion Matrix"),
    "nb_confusion_matrix": ("ma_tran_nham_lan_nb.png", "Naive Bayes Confusion Matrix"),
    "feature_importance": ("bieu_do_dac_trung.png", "Feature Importance"),
}


@performance_bp.get("/performance")
def performance() -> object:
    config = current_app.config["APP_CONFIG"]
    models = current_app.config["DETECTION_SERVICE"].models
    rows, warnings = read_performance_rows(config.PERFORMANCE_FILE)
    current_features = list(FEATURE_NAMES)
    model_features = list(models.feature_columns)
    normalized_model_features = [FEATURE_ALIASES.get(name, name) for name in model_features]
    new_features = [name for name in current_features if name not in normalized_model_features]
    missing_current_features = [
        name for name in model_features if FEATURE_ALIASES.get(name, name) not in current_features
    ]

    if len(model_features) != len(current_features):
        warnings.append(
            "Models need retraining because feature count changed. "
            f"Old feature count = {len(model_features)}. "
            f"New feature count = {len(current_features)}."
        )
    if missing_current_features:
        warnings.append(
            "Model feature columns missing from current extractor: "
            f"{', '.join(missing_current_features)}."
        )
    images = {
        key: image_payload(filename, title)
        for key, (filename, title) in REPORT_IMAGES.items()
    }

    for item in images.values():
        if not item["exists"]:
            warnings.append(f"Missing image file: {item['filename']}")

    return jsonify(
        {
            "success": True,
            "data": {
                "feature_columns": current_features,
                "model_feature_columns": model_features,
                "model_feature_count": len(model_features),
                "current_feature_columns": current_features,
                "feature_count": len(current_features),
                "new_features": new_features,
                "performance_rows": rows,
                "images": images,
                "warnings": warnings,
            },
        }
    ), 200


@performance_bp.get("/performance/image/<path:filename>")
def performance_image(filename: str) -> object:
    path = find_report_image(Path(filename).name)
    if path is None:
        return jsonify({"success": False, "message": "Image file not found."}), 404
    return send_file(path)


def read_performance_rows(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    if not path.exists():
        return [], [f"Missing CSV file: {path.name}"]
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle)), []


def image_payload(filename: str, title: str) -> dict[str, object]:
    path = find_report_image(filename)
    return {
        "filename": filename,
        "title": title,
        "exists": path is not None,
        "url": url_for("performance.performance_image", filename=filename) if path else None,
    }


def find_report_image(filename: str) -> Path | None:
    base_dir = current_app.config["APP_CONFIG"].BASE_DIR if hasattr(current_app.config["APP_CONFIG"], "BASE_DIR") else Path(current_app.root_path)
    candidates = [
        Path(current_app.static_folder or "") / "images" / filename,
        Path(current_app.root_path) / filename,
        Path(base_dir) / filename,
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    return None
