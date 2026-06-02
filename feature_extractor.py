"""Backward-compatible import wrapper for the service feature extractor."""

from services.feature_extractor import (
    FEATURE_NAMES,
    HTML_FEATURE_DEFAULTS,
    URLFeatureExtractor,
    URLValidationError,
    normalize_url,
    validate_public_http_url,
)

__all__ = [
    "FEATURE_NAMES",
    "HTML_FEATURE_DEFAULTS",
    "URLFeatureExtractor",
    "URLValidationError",
    "normalize_url",
    "validate_public_http_url",
]
