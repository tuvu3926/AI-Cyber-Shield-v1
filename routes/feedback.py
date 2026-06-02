"""Feedback API routes."""

from __future__ import annotations

from datetime import datetime

from flask import Blueprint, current_app, jsonify, request

from services.feature_extractor import validate_public_http_url


feedback_bp = Blueprint("feedback", __name__, url_prefix="/api")


@feedback_bp.post("/feedback")
def feedback() -> object:
    payload = request.get_json(silent=True) or {}
    required = {"url", "predicted_result", "user_feedback", "actual_label"}
    missing = sorted(required - payload.keys())
    if missing:
        return jsonify({"success": False, "message": f"Missing fields: {', '.join(missing)}"}), 400

    actual_label = str(payload["actual_label"]).upper()
    if actual_label not in {"PHISHING", "LEGITIMATE"}:
        return jsonify({"success": False, "message": "actual_label is invalid."}), 400

    config = current_app.config["APP_CONFIG"]
    record = {
        "url": validate_public_http_url(str(payload["url"])),
        "predicted_result": str(payload["predicted_result"])[:50],
        "user_feedback": str(payload["user_feedback"])[:500],
        "actual_label": actual_label,
        "ml_label": config.PHISHING_LABEL
        if actual_label == "PHISHING"
        else config.LEGITIMATE_LABEL,
        "forest_risk": payload.get("forest_risk", ""),
        "bayes_risk": payload.get("bayes_risk", ""),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    current_app.config["FEEDBACK_REPO"].append(record)
    return jsonify({"success": True}), 201
