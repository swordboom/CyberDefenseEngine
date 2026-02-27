import re
from urllib.parse import urlsplit

from .privacy import stable_message_fingerprint


class Explainer:
    def __init__(self, cache_store=None, cache_ttl_seconds: int = 3600, hash_salt: str = "cybersaarthi"):
        self.cache = cache_store
        self.cache_ttl_seconds = cache_ttl_seconds
        self.hash_salt = hash_salt

    def _cache_key(self, text: str, url: str, risk_score: float) -> str:
        fingerprint = stable_message_fingerprint(text=text, url=url, hash_salt=self.hash_salt)
        return f"cybersaarthi:explain:{fingerprint}:{round(risk_score, 3)}"

    def explain(self, text: str, url: str, risk_score: float) -> dict:
        cache_key = self._cache_key(text=text, url=url, risk_score=risk_score)
        if self.cache is not None:
            cached = self.cache.get_json(cache_key)
            if cached is not None:
                return cached

        words = text.split()[:12]
        if not words:
            words = ["<url-only-scan>"]
        token_scores = []
        for w in words:
            val = 0.05 + (len(w) / 100)
            if any(k in w.lower() for k in ["verify", "password", "urgent", "account"]):
                val += 0.2
            token_scores.append({"token": w, "importance": round(min(val, 1.0), 4)})

        host = urlsplit(url).hostname or ""
        has_ip = bool(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", host))
        url_feats = {
            "has_at_symbol": "@" in url,
            "has_ip": has_ip,
            "length": len(url),
        }
        if risk_score >= 0.85:
            summary = "Critical phishing risk with strongly suspicious URL and coercive language."
        elif risk_score >= 0.65:
            summary = "High phishing risk due to suspicious URL and social-engineering language patterns."
        elif risk_score >= 0.35:
            summary = "Medium risk: some phishing indicators were found."
        else:
            summary = "Low risk: only weak phishing indicators were detected."
        response = {"top_text_tokens": token_scores, "url_features": url_feats, "summary": summary}
        if self.cache is not None:
            self.cache.set_json(cache_key, response, self.cache_ttl_seconds)
        return response
