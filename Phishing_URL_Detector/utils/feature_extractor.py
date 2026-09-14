import re
import ipaddress
from urllib.parse import urlparse

FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "dot_count", "hyphen_count", "underscore_count", "slash_count",
    "at_count", "question_count", "equal_count", "ampersand_count",
    "percent_count", "digit_count", "letter_count", "subdomain_count",
    "has_ip", "has_https", "has_port", "has_punycode",
    "suspicious_word_count", "entropy"
]

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "signin", "password", "confirm", "bank", "wallet", "bonus",
    "free", "urgent", "security", "authenticate", "webscr", "paypal"
}

def _entropy(value):
    if not value:
        return 0.0
    from math import log2
    counts = {}
    for c in value:
        counts[c] = counts.get(c, 0) + 1
    n = len(value)
    return -sum((count/n) * log2(count/n) for count in counts.values())

def _normalize(url):
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        return "http://" + url
    return url

def extract_features(url):
    raw = url.strip()
    parsed = urlparse(_normalize(raw))
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    try:
        ipaddress.ip_address(host)
        has_ip = 1
    except ValueError:
        has_ip = 0

    subdomain_count = max(0, len(host.split(".")) - 2) if host else 0
    text_lower = raw.lower()
    suspicious_word_count = sum(word in text_lower for word in SUSPICIOUS_WORDS)

    return {
        "url_length": len(raw),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "dot_count": raw.count("."),
        "hyphen_count": raw.count("-"),
        "underscore_count": raw.count("_"),
        "slash_count": raw.count("/"),
        "at_count": raw.count("@"),
        "question_count": raw.count("?"),
        "equal_count": raw.count("="),
        "ampersand_count": raw.count("&"),
        "percent_count": raw.count("%"),
        "digit_count": sum(c.isdigit() for c in raw),
        "letter_count": sum(c.isalpha() for c in raw),
        "subdomain_count": subdomain_count,
        "has_ip": has_ip,
        "has_https": int(parsed.scheme.lower() == "https"),
        "has_port": int(parsed.port is not None) if parsed.hostname else 0,
        "has_punycode": int("xn--" in host.lower()),
        "suspicious_word_count": suspicious_word_count,
        "entropy": round(_entropy(raw), 4)
    }

def extract_feature_vector(url):
    features = extract_features(url)
    return [features[name] for name in FEATURE_NAMES]
