"""URL feature extraction and URL safety validation."""

from __future__ import annotations

import ipaddress
import math
import re
import socket
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

try:
    import whois
except ImportError:  # pragma: no cover - dependency is optional at runtime
    whois = None


FEATURE_NAMES = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "HTTPS_token",
    "Abnormal_URL",
    "port",
    "Favicon",
    "Request_URL",
    "URL_of_Anchor",
    "links_in_tags",
    "sfh",
    "submit_email",
    "Redirect",
    "onmouseover",
    "right_click",
    "popup_window",
    "iframe",
    "Links_pointing_to_page",
    "age_of_domain",
    "dns_record",
    "web_traffic",
    "google_index",
    "statistical_report",
    "url_entropy",
    "typosquatting_score",
    "sensitive_word_count",
]

HTML_FEATURE_DEFAULTS = {
    "Favicon": 1,
    "Request_URL": 1,
    "URL_of_Anchor": 1,
    "links_in_tags": 1,
    "sfh": 1,
    "submit_email": 1,
    "Redirect": 1,
    "onmouseover": 1,
    "right_click": 1,
    "popup_window": 1,
    "iframe": 1,
    "Links_pointing_to_page": 0,
}

SHORTENER_PATTERN = re.compile(
    r"(bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|is\.gd|buff\.ly|adf\.ly|"
    r"bitly\.com|cutt\.ly|rebrand\.ly|s2r\.co|x\.co|lnkd\.in)",
    re.IGNORECASE,
)
PRIVATE_HOSTS = {"localhost", "localhost.localdomain"}
BRAND_KEYWORDS = (
    "paypal",
    "google",
    "facebook",
    "apple",
    "microsoft",
    "amazon",
    "netflix",
    "bank",
)
SENSITIVE_WORDS = (
    "login",
    "signin",
    "verify",
    "account",
    "secure",
    "update",
    "password",
    "bank",
    "wallet",
    "confirm",
)


class URLValidationError(ValueError):
    """Raised when a URL is invalid or unsafe to request."""


@dataclass(frozen=True)
class ParsedUrl:
    url: str
    hostname: str
    domain: str


class URLFeatureExtractor:
    """Extract model features for a public HTTP(S) URL."""

    def __init__(
        self,
        top_domains_file: Path | str | None = None,
        timeout: float = 5,
        max_html_bytes: int = 512 * 1024,
        max_redirects: int = 5,
        enable_google_index_check: bool = False,
    ) -> None:
        self.timeout = timeout
        self.max_html_bytes = max_html_bytes
        self.max_redirects = max_redirects
        self.enable_google_index_check = enable_google_index_check
        self.top_domains = self._load_top_domains(top_domains_file)

    def extract_features(self, url: str, feature_names: list[str] | None = None) -> list[int]:
        feature_map = self.extract_features_labeled(url)
        selected_features = feature_names or FEATURE_NAMES
        return [int(feature_map.get(name, 0)) for name in selected_features]

    def extract_features_labeled(self, url: str) -> dict[str, int]:
        parsed = parse_public_http_url(url)
        html_features = self.extract_html_js_features(parsed.url)
        feature_map = self._build_feature_map(parsed, html_features)
        return {name: int(feature_map.get(name, 0)) for name in FEATURE_NAMES}

    def extract_html_js_features(self, url: str) -> dict[str, int]:
        features = dict(HTML_FEATURE_DEFAULTS)
        try:
            session = requests.Session()
            session.max_redirects = self.max_redirects
            response = session.get(url, timeout=self.timeout, headers={"User-Agent": "AI-Cyber-Shield/1.0"})
            html = response.content[: self.max_html_bytes]
        except requests.RequestException:
            return features

        soup = BeautifulSoup(html, "lxml")
        parsed = urlparse(url)
        base_domain = parsed.hostname or ""

        icons = soup.find_all("link", rel=lambda value: value and "icon" in " ".join(value).lower() if isinstance(value, list) else "icon" in str(value).lower())
        icon_hosts = [urlparse(icon.get("href", "")).hostname for icon in icons if icon.get("href")]
        if any(host and host != base_domain for host in icon_hosts):
            features["Favicon"] = -1

        media_sources = [tag.get(attr) for tag in soup.find_all(["img", "audio", "embed", "iframe"]) for attr in ("src", "data")]
        features["Request_URL"] = ratio_feature(media_sources, base_domain)

        anchors = [tag.get("href") for tag in soup.find_all("a")]
        features["URL_of_Anchor"] = ratio_feature(anchors, base_domain, unsafe_tokens=("#", "javascript:", "mailto:"))

        tags = [tag.get(attr) for tag in soup.find_all(["meta", "script", "link"]) for attr in ("href", "src", "content")]
        features["links_in_tags"] = ratio_feature(tags, base_domain)

        forms = soup.find_all("form")
        if any(is_suspicious_form(form.get("action", ""), base_domain) for form in forms):
            features["sfh"] = -1
        if re.search(r"mailto:", html.decode(errors="ignore"), re.IGNORECASE):
            features["submit_email"] = -1

        text = html.decode(errors="ignore").lower()
        features["Redirect"] = -1 if response.history or "window.location" in text else 1
        features["onmouseover"] = -1 if "onmouseover" in text and "window.status" in text else 1
        features["right_click"] = -1 if "event.button==2" in text or "contextmenu" in text else 1
        features["popup_window"] = -1 if "window.open" in text or "alert(" in text else 1
        features["iframe"] = -1 if soup.find("iframe") else 1
        features["Links_pointing_to_page"] = link_count_feature(anchors, base_domain)
        return features

    def get_domain_age(self, domain: str) -> int | None:
        if whois is None:
            return None
        try:
            data = whois.whois(domain)
            creation_date = data.creation_date
            if isinstance(creation_date, list):
                creation_date = next((item for item in creation_date if item), None)
            if not isinstance(creation_date, datetime):
                return None
            return max((datetime.now() - creation_date.replace(tzinfo=None)).days, 0)
        except Exception:
            return None

    def has_dns_record(self, domain: str) -> int:
        try:
            resolve_public_addresses(domain)
            return 1
        except URLValidationError:
            return -1

    def is_google_indexed(self, domain: str) -> int:
        if not self.enable_google_index_check:
            return 0
        try:
            response = requests.get(
                "https://www.google.com/search",
                params={"q": f"site:{domain}"},
                timeout=self.timeout,
                headers={"User-Agent": "AI-Cyber-Shield/1.0"},
            )
            return 1 if domain in response.text else -1
        except requests.RequestException:
            return 0

    def _build_feature_map(self, parsed: ParsedUrl, html_features: dict[str, int]) -> dict[str, int]:
        url = parsed.url
        hostname = parsed.hostname
        domain = parsed.domain
        parsed_url = urlparse(url)
        domain_age = self.get_domain_age(domain)
        base_hostname = domain
        www_hostname = f"www.{base_hostname}"

        feature_map: dict[str, int] = {
            "having_IP_Address": -1 if is_ip_address(hostname) else 1,
            "URL_Length": length_feature(len(url)),
            "Shortining_Service": -1 if SHORTENER_PATTERN.search(url) else 1,
            "having_At_Symbol": -1 if "@" in url else 1,
            "double_slash_redirecting": -1 if "//" in urlparse(url).path else 1,
            "Prefix_Suffix": -1 if "-" in domain.split(".")[0] else 1,
            "having_Sub_Domain": subdomain_feature(hostname),
            "SSLfinal_State": 1 if parsed_url.scheme == "https" else -1,
            "Domain_registeration_length": 1 if domain_age is not None and domain_age >= 365 else -1 if domain_age is not None else 0,
            "HTTPS_token": -1 if "https" in hostname.replace("https", "", 1).lower() else 1,
            "Abnormal_URL": 1 if domain in hostname else -1,
            "port": -1 if parsed_url.port not in (None, 80, 443) else 1,
            "age_of_domain": 1 if domain_age is not None and domain_age >= 180 else -1 if domain_age is not None else 0,
            "dns_record": self.has_dns_record(domain),
            "web_traffic": 1 if (
                domain in self.top_domains
                or hostname in self.top_domains
                or www_hostname in self.top_domains
            ) else 0,
            "google_index": self.is_google_indexed(domain),
            "statistical_report": -1 if SHORTENER_PATTERN.search(url) or is_ip_address(hostname) else 1,
            "url_entropy": entropy_feature(url),
            "typosquatting_score": typosquatting_feature(hostname),
            "sensitive_word_count": sensitive_word_feature(url),
        }
        feature_map.update(html_features)
        return feature_map

    @staticmethod
    def _load_top_domains(path: Path | str | None) -> set[str]:
        if path is None or not Path(path).exists():
            return set()
        domains: set[str] = set()
        with Path(path).open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                parts = [part.strip().lower() for part in line.split(",") if part.strip()]
                if not parts:
                    continue
                candidate = parts[-1]
                if "." in candidate:
                    domains.add(candidate)
        return domains


def normalize_url(value: str) -> str:
    url = str(value or "").strip()
    
    # Xử lý markdown link
    markdown_link = re.match(r"^\[([^\]]+)\]\(([^)]+)\)$", url)
    if markdown_link:
        url = markdown_link.group(1).strip() or markdown_link.group(2).strip()
    
    # Thêm scheme nếu thiếu
    if url and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", url):
        url = f"https://{url}"
    
    # ✅ Chuẩn hóa www và trailing slash
    parsed = urlparse(url)
    if parsed.hostname:
        hostname = parsed.hostname.lower()
        
        # Thêm www nếu thiếu (chỉ với domain thông thường, không phải subdomain)
        parts = hostname.split(".")
        if len(parts) == 2:  # vd: facebook.com → www.facebook.com
            netloc = f"www.{hostname}"
        else:
            netloc = hostname  # giữ nguyên nếu đã có www hoặc subdomain khác
        
        # Giữ lại port nếu có
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        
        # Bỏ trailing slash ở path
        path = parsed.path.rstrip("/")
        
        # Rebuild URL chuẩn
        url = parsed._replace(netloc=netloc, path=path).geturl()
    
    return url


def validate_public_http_url(url: str) -> str:
    return parse_public_http_url(normalize_url(url)).url


def parse_public_http_url(url: str) -> ParsedUrl:
    normalized = normalize_url(url)
    try:
        parsed = urlparse(normalized)
    except ValueError as error:
        raise URLValidationError("Invalid URL.") from error

    if parsed.scheme not in {"http", "https"}:
        raise URLValidationError("Only public http(s) URLs can be scanned.")
    if parsed.username or parsed.password:
        raise URLValidationError("URLs with embedded credentials are blocked.")
    if not parsed.hostname:
        raise URLValidationError("Enter a domain or URL.")

    hostname = parsed.hostname.lower().rstrip(".")
    if hostname in PRIVATE_HOSTS:
        raise URLValidationError("Private or local network targets are blocked.")
    resolve_public_addresses(hostname)
    if "." not in hostname and not is_ip_address(hostname):
        raise URLValidationError("Enter a domain or URL.")

    return ParsedUrl(url=normalized, hostname=hostname, domain=registered_domain(hostname))


def resolve_public_addresses(hostname: str) -> tuple[str, ...]:
    try:
        addresses = tuple({item[4][0] for item in socket.getaddrinfo(hostname, None)})
    except socket.gaierror as error:
        raise URLValidationError("Domain could not be resolved.") from error
    if not addresses:
        raise URLValidationError("Domain could not be resolved.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise URLValidationError("Private or local network targets are blocked.")
    return addresses


def registered_domain(hostname: str) -> str:
    if is_ip_address(hostname):
        return hostname
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def length_feature(length: int) -> int:
    if length < 54:
        return 1
    if length <= 75:
        return 0
    return -1


def subdomain_feature(hostname: str) -> int:
    if is_ip_address(hostname):
        return -1
    dots = hostname.count(".")
    if dots <= 1:
        return 1
    if dots == 2:
        return 0
    return -1


def ratio_feature(values: list[Any], base_domain: str, unsafe_tokens: tuple[str, ...] = ()) -> int:
    cleaned = [str(value or "").strip() for value in values if str(value or "").strip()]
    if not cleaned:
        return 1
    suspicious = 0
    for value in cleaned:
        lowered = value.lower()
        host = urlparse(value).hostname
        if any(lowered.startswith(token) or lowered == token for token in unsafe_tokens):
            suspicious += 1
        elif host and host != base_domain:
            suspicious += 1
    ratio = suspicious / len(cleaned)
    if ratio < 0.31:
        return 1
    if ratio <= 0.67:
        return 0
    return -1


def is_suspicious_form(action: str, base_domain: str) -> bool:
    action = str(action or "").strip().lower()
    if not action or action in {"about:blank", "#"}:
        return True
    host = urlparse(action).hostname
    return bool(host and host != base_domain)


def link_count_feature(anchors: list[Any], base_domain: str) -> int:
    count = sum(1 for value in anchors if urlparse(str(value or "")).hostname == base_domain)
    if count == 0:
        return -1
    if count <= 2:
        return 0
    return 1


def entropy_feature(url: str) -> int:
    text = str(url or "")
    if not text:
        return 1
    entropy = 0.0
    for char in set(text):
        probability = text.count(char) / len(text)
        entropy -= probability * math.log2(probability)
    if entropy < 4.2:
        return 1
    if entropy <= 4.8:
        return 0
    return -1


def typosquatting_feature(hostname: str) -> int:
    normalized = re.sub(r"[^a-z0-9]", "", hostname.lower())
    suspicious = 0
    for brand in BRAND_KEYWORDS:
        if brand in normalized and brand not in hostname.lower().split("."):
            suspicious += 1
        elif levenshtein_distance(normalized[: len(brand) + 2], brand) == 1:
            suspicious += 1
    if suspicious == 0:
        return 1
    if suspicious == 1:
        return 0
    return -1


def sensitive_word_feature(url: str) -> int:
    normalized = str(url or "").lower()
    count = sum(1 for word in SENSITIVE_WORDS if word in normalized)
    if count <= 1:
        return 1
    if count <= 3:
        return 0
    return -1


def levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, 1):
        current = [i]
        for j, right_char in enumerate(right, 1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (left_char != right_char),
                )
            )
        previous = current
    return previous[-1]
