from datetime import datetime

from .config import Settings
from .schemas import MetricsSummaryResponse
from .storage import (
    Database,
    get_aggregated_summary,
    get_user_trend,
    record_metric_event,
    seed_institutions,
)


class MetricsManager:
    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db

    def bootstrap(self) -> None:
        self.db.init_schema()
        with self.db.session() as session:
            seed_institutions(
                session,
                seeds=self.settings.institution_seed_json,
                hash_salt=self.settings.hash_salt,
            )

    def record_event(
        self,
        *,
        institution_id: str,
        risk_score: float,
        risk_bucket: str,
        hashed_user_id: str | None,
        event_time: datetime | None = None,
    ) -> None:
        with self.db.session() as session:
            record_metric_event(
                session,
                institution_id=institution_id,
                risk_score=risk_score,
                risk_bucket=risk_bucket,
                hashed_user_id=hashed_user_id,
                event_time=event_time,
            )

    def get_summary(self, *, institution_id: str, since_hours: int = 24 * 7) -> MetricsSummaryResponse:
        with self.db.session() as session:
            summary = get_aggregated_summary(session, institution_id=institution_id, since_hours=since_hours)
        return MetricsSummaryResponse(**summary)

    def get_user_trend(self, *, institution_id: str, hashed_user_id: str) -> list[float]:
        with self.db.session() as session:
            return get_user_trend(session, institution_id=institution_id, hashed_user_id=hashed_user_id)
