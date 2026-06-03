"""Scan API routes."""

from __future__ import annotations

import logging

from flask import Blueprint, current_app, jsonify, request

from services.feature_extractor import URLValidationError, normalize_url


LOGGER = logging.getLogger(__name__)

scan_bp = Blueprint("scan", __name__, url_prefix="/api")

_VALIDATION_MESSAGES = {
    "could not be resolved": "Domain không tồn tại hoặc đã bị gỡ xuống.",
    "Private or local": "Không thể quét địa chỉ nội bộ hoặc local.",
    "Only public http": "Chỉ hỗ trợ URL dạng http hoặc https.",
    "embedded credentials": "URL chứa thông tin đăng nhập — không được phép quét.",
    "Enter a domain": "Vui lòng nhập một URL hợp lệ.",
}


def _friendly_message(error: URLValidationError) -> str:
    raw = str(error)
    for keyword, message in _VALIDATION_MESSAGES.items():
        if keyword.lower() in raw.lower():
            return message
    return raw


@scan_bp.post("/scan")
def scan() -> tuple[object, int] | object:
    payload = request.get_json(silent=True) or {}
    original_url = str(payload.get("url", "")).strip()
    url = normalize_url(original_url)

    if not url:
        return jsonify({"success": False, "message": "URL is required."}), 400

    try:
        result = current_app.config["DETECTION_SERVICE"].analyze_url(url, original_url=original_url)
        return jsonify({"success": True, "data": result}), 200

    except URLValidationError as exc:
        return jsonify({"success": False, "message": _friendly_message(exc)}), 422

    except RuntimeError as exc:
        LOGGER.error("Detection pipeline error for url=%s: %s", url, exc)
        return jsonify({"success": False, "message": "Lỗi hệ thống khi phân tích URL."}), 500

    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("Unexpected error for url=%s", url)
        return jsonify({"success": False, "message": "Đã xảy ra lỗi không mong muốn."}), 500