import json
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .security import hash_api_key


class Base(DeclarativeBase):
    pass


class Institution(Base):
    __tablename__ = "institutions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    plan_type: Mapped[str] = mapped_column(String(32), nullable=False, default="free")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class AggregatedMetric(Base):
    __tablename__ = "aggregated_metrics"
    __table_args__ = (
        UniqueConstraint("institution_id", "risk_bucket", "timestamp", name="uq_agg_metric_bucket_ts"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    institution_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("institutions.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    risk_bucket: Mapped[str] = mapped_column(String(16), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_sum: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)


class UserTrend(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("hashed_user_id", "institution_id", name="uq_user_institution"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hashed_user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    institution_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("institutions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    risk_score_trend: Mapped[list[float]] = mapped_column(JSON, nullable=False, default=list)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class Database:
    def __init__(self, database_url: str):
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine = create_engine(database_url, pool_pre_ping=True, connect_args=connect_args)
        self.SessionLocal = sessionmaker(bind=self.engine, autoflush=False, autocommit=False, expire_on_commit=False)

    def init_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        db = self.SessionLocal()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


def seed_institutions(db: Session, *, seeds: dict[str, dict[str, str]], hash_salt: str) -> None:
    for institution_name, config in seeds.items():
        name = institution_name.strip()
        if not name:
            continue
        api_key = str(config.get("api_key", "")).strip()
        if not api_key:
            continue
        plan_type = str(config.get("plan_type", "free")).strip() or "free"
        existing = db.execute(select(Institution).where(Institution.name == name)).scalar_one_or_none()
        if existing is not None:
            continue
        institution = Institution(
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"cyberdefenseengine:{name}")),
            name=name,
            api_key_hash=hash_api_key(api_key, hash_salt),
            plan_type=plan_type,
        )
        db.add(institution)


def get_institution_by_api_key(db: Session, *, api_key: str, hash_salt: str) -> Institution | None:
    hashed = hash_api_key(api_key, hash_salt)
    return db.execute(select(Institution).where(Institution.api_key_hash == hashed)).scalar_one_or_none()


def aggregate_minute(ts: datetime | None = None) -> datetime:
    now = ts or datetime.now(tz=UTC)
    return now.astimezone(UTC).replace(second=0, microsecond=0)


def record_metric_event(
    db: Session,
    *,
    institution_id: str,
    risk_bucket: str,
    risk_score: float,
    hashed_user_id: str | None = None,
    event_time: datetime | None = None,
) -> None:
    minute_bucket = aggregate_minute(event_time)
    existing = db.execute(
        select(AggregatedMetric).where(
            AggregatedMetric.institution_id == institution_id,
            AggregatedMetric.risk_bucket == risk_bucket,
            AggregatedMetric.timestamp == minute_bucket,
        )
    ).scalar_one_or_none()
    if existing is None:
        db.add(
            AggregatedMetric(
                institution_id=institution_id,
                risk_bucket=risk_bucket,
                timestamp=minute_bucket,
                count=1,
                risk_sum=float(risk_score),
            )
        )
    else:
        existing.count += 1
        existing.risk_sum += float(risk_score)

    if hashed_user_id:
        user_row = db.execute(
            select(UserTrend).where(
                UserTrend.hashed_user_id == hashed_user_id,
                UserTrend.institution_id == institution_id,
            )
        ).scalar_one_or_none()
        if user_row is None:
            db.add(
                UserTrend(
                    hashed_user_id=hashed_user_id,
                    institution_id=institution_id,
                    risk_score_trend=[float(risk_score)],
                )
            )
        else:
            trend = list(user_row.risk_score_trend or [])
            trend.append(float(risk_score))
            user_row.risk_score_trend = trend[-30:]


def get_aggregated_summary(
    db: Session,
    *,
    institution_id: str,
    since_hours: int,
) -> dict:
    since = datetime.now(tz=UTC) - timedelta(hours=since_hours)
    rows = db.execute(
        select(
            AggregatedMetric.risk_bucket,
            func.sum(AggregatedMetric.count),
            func.sum(AggregatedMetric.risk_sum),
        ).where(
            AggregatedMetric.institution_id == institution_id,
            AggregatedMetric.timestamp >= since,
        ).group_by(AggregatedMetric.risk_bucket)
    ).all()

    buckets = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    total = 0
    risk_sum = 0.0
    for risk_bucket, count_value, risk_sum_value in rows:
        count_num = int(count_value or 0)
        buckets[str(risk_bucket)] = count_num
        total += count_num
        risk_sum += float(risk_sum_value or 0.0)

    high_risk_total = buckets.get("high", 0) + buckets.get("critical", 0)
    return {
        "institution_id": institution_id,
        "total_requests": total,
        "avg_risk": round((risk_sum / total), 4) if total else 0.0,
        "high_risk_rate": round((high_risk_total / total), 4) if total else 0.0,
        "buckets": buckets,
    }


def get_user_trend(db: Session, *, institution_id: str, hashed_user_id: str) -> list[float]:
    row = db.execute(
        select(UserTrend).where(
            UserTrend.hashed_user_id == hashed_user_id,
            UserTrend.institution_id == institution_id,
        )
    ).scalar_one_or_none()
    if row is None:
        return []
    trend = row.risk_score_trend
    if isinstance(trend, str):
        try:
            parsed = json.loads(trend)
            if isinstance(parsed, list):
                return [float(item) for item in parsed]
        except json.JSONDecodeError:
            return []
    if isinstance(trend, list):
        return [float(item) for item in trend]
    return []
