
"""Scan API routes."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from services.feature_extractor import normalize_url


scan_bp = Blueprint("scan", __name__, url_prefix="/api")


@scan_bp.post("/scan")
def scan() -> tuple[object, int] | object:
    payload = request.get_json(silent=True) or {}
    original_url = str(payload.get("url", "")).strip()
    url = normalize_url(original_url)
    if not url:
        return jsonify({"success": False, "message": "URL is required."}), 400

    result = current_app.config["DETECTION_SERVICE"].analyze_url(url, original_url=original_url)
    return jsonify({"success": True, "data": result}), 200
