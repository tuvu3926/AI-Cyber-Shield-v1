import services.feature_extractor as feature_module
from config import Config
from services.feature_extractor import HTML_FEATURE_DEFAULTS, URLFeatureExtractor
from services.model_loader import load_models


def test_model_feature_columns_match():
    models = load_models(Config.RF_MODEL_FILE, Config.NB_MODEL_FILE)

    assert models.feature_columns


def test_extractor_outputs_expected_feature_count(monkeypatch):
    extractor = URLFeatureExtractor(Config.TOP_DOMAINS_FILE)
    monkeypatch.setattr(feature_module, "resolve_public_addresses", lambda _domain: ("93.184.216.34",))
    monkeypatch.setattr(
        extractor,
        "extract_html_js_features",
        lambda _url: dict(HTML_FEATURE_DEFAULTS),
    )
    monkeypatch.setattr(extractor, "get_domain_age", lambda _domain: 365)
    monkeypatch.setattr(extractor, "has_dns_record", lambda _domain: 1)
    monkeypatch.setattr(extractor, "is_google_indexed", lambda _domain: 0)

    models = load_models(Config.RF_MODEL_FILE, Config.NB_MODEL_FILE)
    features = extractor.extract_features("https://example.com/", models.feature_columns)

    assert len(features) == len(models.feature_columns)
