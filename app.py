"""Flask application entrypoint for AI Cyber Shield."""

from __future__ import annotations

import logging

from flask import Flask, jsonify, render_template
from werkzeug.exceptions import HTTPException

from config import Config
from routes.feedback import feedback_bp
from routes.history import history_bp
from routes.performance import performance_bp
from routes.scan import scan_bp
from services.detector import DetectionService
from services.feature_extractor import URLFeatureExtractor, URLValidationError
from services.model_loader import load_models
from services.storage import CsvRepository


def create_app(config_class: type[Config] = Config) -> Flask:
    """Create and configure the Flask application."""

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    app = Flask(__name__)
    app.config.from_object(config_class)
    app.config["APP_CONFIG"] = config_class

    history_repo = CsvRepository(config_class.HISTORY_FILE, config_class.HISTORY_COLUMNS)
    feedback_repo = CsvRepository(config_class.FEEDBACK_FILE, config_class.FEEDBACK_COLUMNS)
    models = load_models(config_class.RF_MODEL_FILE, config_class.NB_MODEL_FILE)
    extractor = URLFeatureExtractor(
        top_domains_file=config_class.TOP_DOMAINS_FILE,
        timeout=config_class.REQUEST_TIMEOUT_SECONDS,
        max_html_bytes=config_class.MAX_HTML_BYTES,
        max_redirects=config_class.MAX_REDIRECTS,
        enable_google_index_check=config_class.ENABLE_GOOGLE_INDEX_CHECK,
    )

    app.config["HISTORY_REPO"] = history_repo
    app.config["FEEDBACK_REPO"] = feedback_repo
    app.config["DETECTION_SERVICE"] = DetectionService(
        models=models,
        extractor=extractor,
        history_repo=history_repo,
        phishing_label=config_class.PHISHING_LABEL,
        threshold=config_class.PHISHING_THRESHOLD,
    )

    app.register_blueprint(scan_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(feedback_bp)
    app.register_blueprint(performance_bp)
    register_error_handlers(app)

    @app.get("/")
    def home() -> str:
        return render_template("index.html")

    return app


def register_error_handlers(app: Flask) -> None:
    """Register centralized JSON error responses for API routes."""

    @app.errorhandler(URLValidationError)
    def handle_url_validation(error: URLValidationError) -> tuple[object, int]:
        return jsonify({"success": False, "message": str(error)}), 400

    @app.errorhandler(ValueError)
    def handle_value_error(error: ValueError) -> tuple[object, int]:
        return jsonify({"success": False, "message": str(error)}), 400

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException) -> tuple[object, int]:
        return (
            jsonify({"success": False, "message": error.description}),
            error.code or 500,
        )

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception) -> tuple[object, int]:
        app.logger.exception("Unhandled application error: %s", error)
        return jsonify({"success": False, "message": "Internal server error."}), 500


app = create_app()


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG)
