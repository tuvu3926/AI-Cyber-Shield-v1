"""Command-line URL analyzer for AI Cyber Shield."""

from __future__ import annotations

import sys

from config import Config
from services.detector import DetectionService
from services.feature_extractor import URLFeatureExtractor
from services.model_loader import load_models
from services.storage import CsvRepository


def build_detector() -> DetectionService:
    models = load_models(Config.RF_MODEL_FILE, Config.NB_MODEL_FILE)
    extractor = URLFeatureExtractor(
        top_domains_file=Config.TOP_DOMAINS_FILE,
        timeout=Config.REQUEST_TIMEOUT_SECONDS,
        max_html_bytes=Config.MAX_HTML_BYTES,
        max_redirects=Config.MAX_REDIRECTS,
        enable_google_index_check=Config.ENABLE_GOOGLE_INDEX_CHECK,
    )
    history_repo = CsvRepository(Config.HISTORY_FILE, Config.HISTORY_COLUMNS)
    return DetectionService(
        models=models,
        extractor=extractor,
        history_repo=history_repo,
        phishing_label=Config.PHISHING_LABEL,
        threshold=Config.PHISHING_THRESHOLD,
    )


def analyze(url: str) -> None:
    result = build_detector().analyze_url(url)
    print(f"Prediction: {result['final_result']}")
    print(f"Random Forest risk: {result['forest_risk']}%")
    print(f"Naive Bayes risk: {result['bayes_risk']}%")


if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else input("Enter a URL to analyze: ").strip()
    if target_url:
        analyze(target_url)
