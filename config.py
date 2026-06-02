"""Application configuration for AI Cyber Shield."""

from __future__ import annotations

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


class Config:
    """Runtime configuration loaded from environment variables."""

    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
    JSON_SORT_KEYS = False
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(16 * 1024)))

    DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
    MODEL_DIR = Path(os.getenv("MODEL_DIR", BASE_DIR / "models"))

    HISTORY_FILE = Path(os.getenv("HISTORY_FILE", DATA_DIR / "scan_history.csv"))
    FEEDBACK_FILE = Path(os.getenv("FEEDBACK_FILE", DATA_DIR / "feedback.csv"))
    RF_MODEL_FILE = Path(os.getenv("RF_MODEL_FILE", MODEL_DIR / "best_model.pkl"))
    NB_MODEL_FILE = Path(os.getenv("NB_MODEL_FILE", MODEL_DIR / "naive_bayes_model.pkl"))
    TOP_DOMAINS_FILE = Path(
        os.getenv("TOP_DOMAINS_FILE", DATA_DIR / "top_10000_domains.csv")
    )
    PERFORMANCE_FILE = Path(os.getenv("PERFORMANCE_FILE", BASE_DIR / "ket_qua_so_sanh.csv"))

    PHISHING_LABEL = 0
    LEGITIMATE_LABEL = 1
    PHISHING_THRESHOLD = float(os.getenv("PHISHING_THRESHOLD", "0.85"))

    REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "5"))
    MAX_HTML_BYTES = int(os.getenv("MAX_HTML_BYTES", str(512 * 1024)))
    MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "5"))
    ENABLE_GOOGLE_INDEX_CHECK = os.getenv("ENABLE_GOOGLE_INDEX_CHECK", "0") == "1"

    HISTORY_COLUMNS = [
        "url",
        "forest_result",
        "forest_risk",
        "bayes_result",
        "bayes_risk",
        "final_result",
        "time",
    ]

    FEEDBACK_COLUMNS = [
        "url",
        "predicted_result",
        "user_feedback",
        "actual_label",
        "ml_label",
        "forest_risk",
        "bayes_risk",
        "timestamp",
    ]
