"""Phishing detection orchestration."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import pandas as pd

from services.feature_extractor import URLFeatureExtractor, normalize_url, validate_public_http_url
from services.model_loader import LoadedModels
from services.storage import CsvRepository


FEATURE_ALIASES = {
    "url_entropy_label": "url_entropy",
    "typosquatting_label": "typosquatting_score",
    "sensitive_word_label": "sensitive_word_count",
}

LOGGER = logging.getLogger(__name__)
NB_HIGH_CONFIDENCE_WARNING_THRESHOLD = 0.95
NB_SAFE_DOMAIN_CAP = 0.50


class DetectionService:
    """Runs feature extraction, model inference, and history persistence."""

    def __init__(
        self,
        models: LoadedModels,
        extractor: URLFeatureExtractor,
        history_repo: CsvRepository,
        phishing_label: int,
        threshold: float,
    ) -> None:
        self.models = models
        self.extractor = extractor
        self.history_repo = history_repo
        self.phishing_label = phishing_label
        self.threshold = threshold

    def analyze_url(self, url: str, original_url: str | None = None) -> dict[str, Any]:
        cleaned_url = validate_public_http_url(normalize_url(url))
        feature_values = self.extractor.extract_features_labeled(cleaned_url)
        model_features = [self._feature_value(feature_values, column) for column in self.models.feature_columns]
        self._validate_feature_shape(model_features)

        feature_df = pd.DataFrame([model_features], columns=self.models.feature_columns)
        forest_risk = self._risk_from_model(self.models.random_forest, feature_df)
        bayes_feature_df = self._scaled_naive_bayes_features(feature_df)
        bayes_risk = self._risk_from_model(self.models.naive_bayes, bayes_feature_df)
        bayes_risk = self._checked_bayes_risk(cleaned_url, feature_values, forest_risk, bayes_risk)
        forest_result = self._label_from_risk(forest_risk)
        bayes_result = self._label_from_risk(bayes_risk)

        result = {
            "url": cleaned_url,
            "original_url": original_url if original_url is not None else url,
            "features": feature_values,
            "model_feature_count": len(self.models.feature_columns),
            "current_feature_count": len(feature_values),
            "forest_result": forest_result,
            "forest_risk": round(forest_risk * 100, 2),
            "bayes_result": bayes_result,
            "bayes_risk": round(bayes_risk * 100, 2),
            "average_risk": round(((forest_risk + bayes_risk) / 2) * 100, 2),
            "final_result": self._final_verdict(forest_result, bayes_result),
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.history_repo.append(result)
        return result

    def _scaled_naive_bayes_features(self, feature_df: pd.DataFrame) -> pd.DataFrame:
        scaler = self.models.naive_bayes_scaler
        if scaler is None:
            return feature_df
        scaled = scaler.transform(feature_df)
        return pd.DataFrame(scaled, columns=feature_df.columns)

    def _checked_bayes_risk(
        self,
        cleaned_url: str,
        feature_values: dict[str, int],
        forest_risk: float,
        bayes_risk: float,
    ) -> float:
        if bayes_risk <= NB_HIGH_CONFIDENCE_WARNING_THRESHOLD or not self._known_safe_domain(cleaned_url, feature_values):
            return bayes_risk

        LOGGER.warning(
            "Naive Bayes high-confidence phishing prediction on known safe domain: url=%s bayes_risk=%.4f forest_risk=%.4f",
            cleaned_url,
            bayes_risk,
            forest_risk,
        )

        if forest_risk < self.threshold:
            return min(bayes_risk, NB_SAFE_DOMAIN_CAP)
        return bayes_risk

    def _known_safe_domain(self, cleaned_url: str, feature_values: dict[str, int]) -> bool:
        parsed = urlparse(cleaned_url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        base = hostname.removeprefix("www.")
        www_host = f"www.{base}"
        in_top = (
            hostname in self.extractor.top_domains
            or base in self.extractor.top_domains
            or www_host in self.extractor.top_domains
        )
        return bool(in_top)

    def _validate_feature_shape(self, features: list[int]) -> None:
        expected = len(self.models.feature_columns)
        actual = len(features)
        if actual != expected:
            raise RuntimeError(f"Feature mismatch: expected {expected}, got {actual}.")

    @staticmethod
    def _feature_value(features: dict[str, int], column: str) -> int:
        if column in features:
            return int(features[column])
        alias = FEATURE_ALIASES.get(column)
        if alias and alias in features:
            return int(features[alias])
        return 0

    def _risk_from_model(self, model: Any, feature_df: pd.DataFrame) -> float:
        probabilities = model.predict_proba(feature_df)[0]
        classes = list(model.classes_)
        phishing_label = self.phishing_label if self.phishing_label in classes else None
        if phishing_label is None:
            if len(classes) == 2:
                phishing_label = classes[0]
            else:
                raise RuntimeError("Model is missing the phishing class label.")
        return float(probabilities[classes.index(phishing_label)])

    def _label_from_risk(self, risk: float) -> str:
        return "PHISHING" if risk >= self.threshold else "LEGITIMATE"

    @staticmethod
    def _final_verdict(forest_result: str, bayes_result: str) -> str:
        if forest_result == "PHISHING" and bayes_result == "PHISHING":
            return "HIGH RISK"
        if forest_result == "PHISHING" or bayes_result == "PHISHING":
            return "MEDIUM RISK"   # một trong hai nghi ngờ → cảnh báo
        return "SAFE" 
