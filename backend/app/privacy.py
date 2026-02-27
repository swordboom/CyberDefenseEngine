from urllib.parse import urlsplit, urlunsplit

from .security import hash_identifier


def normalize_url(url: str) -> str:
    try:
        parsed = urlsplit(url.strip())
        netloc = parsed.netloc.lower()
        scheme = parsed.scheme.lower()
        return urlunsplit((scheme, netloc, parsed.path, "", ""))
    except Exception:
        return url.strip().lower()


def stable_message_fingerprint(text: str, url: str, hash_salt: str) -> str:
    normalized_text = text.strip()
    normalized_url = normalize_url(url)
    payload = f"{normalized_url}|len={len(normalized_text)}"
    return hash_identifier(payload, hash_salt)


def to_risk_bucket(score: float) -> str:
    if score >= 0.85:
        return "critical"
    if score >= 0.65:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"
