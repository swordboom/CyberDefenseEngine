from datetime import UTC, datetime
from typing import Literal

from pydantic import AnyHttpUrl, BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    text: str = Field(default="", max_length=4096)
    url: AnyHttpUrl = Field(max_length=2048)
    hashed_user_id: str | None = Field(default=None, min_length=32, max_length=128)

    @field_validator("text")
    @classmethod
    def _normalize_text(cls, value: str) -> str:
        return value.strip()

    @field_validator("hashed_user_id")
    @classmethod
    def _normalize_hashed_user_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        return normalized or None


class InferenceRequest(BaseModel):
    text: str = Field(default="", max_length=4096)
    url: AnyHttpUrl = Field(max_length=2048)


class InferenceResponse(BaseModel):
    risk_score: float = Field(ge=0.0, le=1.0)
    prediction: Literal["phishing", "benign"]
    risk_bucket: Literal["low", "medium", "high", "critical"]
    inference_latency_ms: float = Field(ge=0.0)
    model_backend: Literal["onnx", "torch", "heuristic"]


class InferenceBatchRequest(BaseModel):
    items: list[InferenceRequest] = Field(min_length=1, max_length=256)


class InferenceBatchResponse(BaseModel):
    items: list[InferenceResponse]


class AnalyzeResponse(BaseModel):
    risk_score: float = Field(ge=0.0, le=1.0)
    prediction: Literal["phishing", "benign"]
    risk_bucket: Literal["low", "medium", "high", "critical"]
    inference_latency_ms: float = Field(ge=0.0)
    model_backend: Literal["onnx", "torch", "heuristic"]
    hashed_id: str = Field(min_length=64, max_length=64)


class TokenImportance(BaseModel):
    token: str
    importance: float = Field(ge=0.0, le=1.0)


class UrlFeatures(BaseModel):
    has_at_symbol: bool
    has_ip: bool
    length: int = Field(ge=0)


class ExplainRequest(BaseModel):
    text: str = Field(default="", max_length=4096)
    url: AnyHttpUrl = Field(max_length=2048)
    risk_score: float = Field(ge=0.0, le=1.0)

    @field_validator("text")
    @classmethod
    def _normalize_text(cls, value: str) -> str:
        return value.strip()


class ExplainResponse(BaseModel):
    top_text_tokens: list[TokenImportance]
    url_features: UrlFeatures
    summary: str


class MetricsEventRequest(BaseModel):
    institution_id: str = Field(min_length=1, max_length=64)
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_bucket: Literal["low", "medium", "high", "critical"]
    hashed_user_id: str | None = Field(default=None, min_length=32, max_length=128)
    event_time: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class MetricsSummaryResponse(BaseModel):
    institution_id: str
    total_requests: int = Field(ge=0)
    avg_risk: float = Field(ge=0.0, le=1.0)
    high_risk_rate: float = Field(ge=0.0, le=1.0)
    buckets: dict[str, int]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class TokenRequest(BaseModel):
    role: Literal["student", "admin"] = "student"
    hashed_user_id: str | None = Field(default=None, min_length=32, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int = Field(ge=60)
    institution_id: str
    role: Literal["student", "admin"]


class ApiKeyValidationRequest(BaseModel):
    api_key: str = Field(min_length=8, max_length=256)


class TokenValidationRequest(BaseModel):
    token: str


class AuthContextResponse(BaseModel):
    institution_id: str
    institution_name: str
    plan_type: str
    role: Literal["student", "admin"] = "student"
    hashed_user_id: str | None = None


class MetricsResponse(BaseModel):
    institution_id: str
    total_requests: int = Field(ge=0)
    avg_risk: float = Field(ge=0.0, le=1.0)
    high_risk_rate: float = Field(ge=0.0, le=1.0)
    buckets: dict[str, int]


class BlacklistResponse(BaseModel):
    domains: list[str]
    updated_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
