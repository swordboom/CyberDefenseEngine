import json
from functools import lru_cache
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        protected_namespaces=("settings_",),
        extra="ignore",
    )

    app_name: str = "CyberSaarthi Gateway"
    app_version: str = "2.0.0"
    app_env: str = "development"
    log_level: str = "INFO"
    service_name: str = "gateway"
    service_mode: str = "inprocess"  # inprocess | http
    enable_docs: bool = True
    enable_gzip: bool = True
    max_payload_bytes: int = Field(default=32768, ge=1024, le=10485760)

    model_name: str = "distilbert-base-uncased"
    hf_token: str | None = None
    max_length: int = Field(default=256, ge=32, le=1024)
    onnx_path: str = "artifacts/distilbert_phishing.onnx"
    onnx_quantized_path: str | None = None
    onnx_intra_op_threads: int = Field(default=0, ge=0, le=256)
    onnx_inter_op_threads: int = Field(default=0, ge=0, le=256)
    onnx_providers: list[str] = Field(default_factory=lambda: ["CPUExecutionProvider"])
    force_heuristic: bool = False

    risk_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    high_risk_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    hash_salt: str = "cybersaarthi-change-me"
    text_max_length: int = Field(default=4096, ge=1, le=32768)
    url_max_length: int = Field(default=2048, ge=8, le=4096)

    database_url: str = "sqlite:///./artifacts/cybersaarthi.db"
    redis_url: str = "redis://localhost:6379/0"
    redis_enabled: bool = True
    rate_limit_per_minute: int = Field(default=120, ge=1, le=50000)
    explanation_cache_ttl_seconds: int = Field(default=3600, ge=60, le=86400)

    require_api_key: bool = False
    default_institution_name: str = "public-dev"
    institution_seed_json: dict[str, dict[str, str]] = Field(
        default_factory=lambda: {
            "public-dev": {"api_key": "local-dev-key", "plan_type": "free"},
            "demo-university": {"api_key": "demo-admin-key", "plan_type": "pro"},
        }
    )

    jwt_secret: str = "change-me-jwt-secret"
    jwt_algorithm: str = "HS256"
    jwt_exp_minutes: int = Field(default=60, ge=5, le=1440)

    internal_service_token: str = "change-me-internal-token"
    gateway_service_timeout_ms: int = Field(default=2500, ge=100, le=30000)
    inference_service_url: str = "http://inference:8001"
    explanation_service_url: str = "http://explanation:8002"
    metrics_service_url: str = "http://metrics:8003"
    auth_service_url: str = "http://auth:8004"

    domain_blacklist: list[str] = Field(
        default_factory=lambda: [
            "secure-login-update.com",
            "verify-account-now.net",
            "update-banking-access.org",
        ]
    )

    cors_allow_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000", "http://127.0.0.1:5173"]
    )
    cors_allow_methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "OPTIONS"])
    cors_allow_headers: list[str] = Field(
        default_factory=lambda: ["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"]
    )
    trusted_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost", "testserver"])

    @field_validator("log_level")
    @classmethod
    def _normalize_log_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        normalized = value.strip().upper()
        if normalized not in allowed:
            raise ValueError(f"log_level must be one of: {sorted(allowed)}")
        return normalized

    @field_validator("service_mode")
    @classmethod
    def _validate_service_mode(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"inprocess", "http"}:
            raise ValueError("service_mode must be one of: inprocess, http")
        return normalized

    @field_validator(
        "onnx_providers",
        "cors_allow_origins",
        "cors_allow_methods",
        "cors_allow_headers",
        "trusted_hosts",
        "domain_blacklist",
        mode="before",
    )
    @classmethod
    def _parse_list_setting(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                parsed = json.loads(stripped)
                if not isinstance(parsed, list):
                    raise ValueError("Expected a JSON list")
                return [str(item).strip() for item in parsed if str(item).strip()]
            return [item.strip() for item in stripped.split(",") if item.strip()]
        if isinstance(value, (list, tuple, set)):
            return [str(item).strip() for item in value if str(item).strip()]
        raise ValueError("List setting must be a list, JSON list, or comma-separated string")

    @field_validator("institution_seed_json", mode="before")
    @classmethod
    def _parse_seed_json(cls, value: Any) -> dict[str, dict[str, str]]:
        if value is None:
            return {}
        if isinstance(value, dict):
            parsed: dict[str, dict[str, str]] = {}
            for name, item in value.items():
                if isinstance(item, dict):
                    api_key = str(item.get("api_key", "")).strip()
                    plan_type = str(item.get("plan_type", "free")).strip() or "free"
                else:
                    api_key = str(item).strip()
                    plan_type = "free"
                if api_key:
                    parsed[str(name).strip()] = {"api_key": api_key, "plan_type": plan_type}
            return parsed
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return {}
            loaded = json.loads(stripped)
            if not isinstance(loaded, dict):
                raise ValueError("institution_seed_json must be a JSON object")
            return cls._parse_seed_json(loaded)
        raise ValueError("institution_seed_json must be a dict or JSON object string")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
