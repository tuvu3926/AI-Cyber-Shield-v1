from pathlib import Path

import pytest

from services.feature_extractor import URLValidationError, normalize_url, validate_public_http_url
from services.storage import CsvRepository


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://10.0.0.1/",
        "ftp://example.com/",
        "https://user:pass@example.com/",
    ],
)
def test_validate_public_http_url_rejects_unsafe_targets(url):
    with pytest.raises(URLValidationError):
        validate_public_http_url(url)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("facebook.com", "https://facebook.com"),
        ("[www.google.com](http://www.google.com)", "https://www.google.com"),
        ("https://github.com", "https://github.com"),
    ],
)
def test_validate_public_http_url_accepts_normalized_domains(monkeypatch, url, expected):
    monkeypatch.setattr(
        "services.feature_extractor.resolve_public_addresses",
        lambda _hostname: ("93.184.216.34",),
    )

    assert validate_public_http_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "invalid text",
        "abc",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "ftp://example.com",
    ],
)
def test_validate_public_http_url_rejects_invalid_inputs(monkeypatch, url):
    monkeypatch.setattr(
        "services.feature_extractor.resolve_public_addresses",
        lambda _hostname: ("93.184.216.34",),
    )

    with pytest.raises(URLValidationError):
        validate_public_http_url(url)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("facebook.com", "https://facebook.com"),
        ("www.facebook.com", "https://www.facebook.com"),
        ("google.com.vn", "https://google.com.vn"),
        ("youtube.com", "https://youtube.com"),
    ],
)
def test_normalize_url_adds_https_to_domains(url, expected):
    assert normalize_url(url) == expected


def test_csv_repository_neutralizes_formula_values(tmp_path: Path):
    repo = CsvRepository(tmp_path / "out.csv", ["url"])
    repo.append({"url": "=cmd|calc"})

    rows = repo.list_records()
    assert rows[0]["url"] == "'=cmd|calc"
