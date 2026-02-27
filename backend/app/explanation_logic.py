from .config import Settings
from .explain import Explainer
from .redis_utils import CacheStore
from .schemas import ExplainResponse


class ExplanationManager:
    def __init__(self, settings: Settings, cache: CacheStore):
        self.explainer = Explainer(
            cache_store=cache,
            cache_ttl_seconds=settings.explanation_cache_ttl_seconds,
            hash_salt=settings.hash_salt,
        )

    def explain(self, *, text: str, url: str, risk_score: float) -> ExplainResponse:
        response = self.explainer.explain(text=text, url=url, risk_score=risk_score)
        return ExplainResponse(**response)
