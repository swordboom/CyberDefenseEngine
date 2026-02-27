import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from .auth_logic import AuthContext, AuthManager
from .config import Settings, settings as default_settings
from .explanation_logic import ExplanationManager
from .http_utils import add_common_handlers, configure_logging
from .inference_logic import InferenceManager
from .metrics_logic import MetricsManager
from .observability import add_prometheus
from .privacy import stable_message_fingerprint
from .redis_utils import CacheStore, RateLimiter, build_redis_client
from .schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    AuthContextResponse,
    BlacklistResponse,
    ExplainResponse,
    InferenceResponse,
    MetricsResponse,
    MetricsSummaryResponse,
    RuntimeModeResponse,
    TokenRequest,
    TokenResponse,
)
from .security import hash_identifier
from .service_client import InternalServiceClient, ServiceCallError
from .storage import Database

logger = logging.getLogger(__name__)


@dataclass
class GatewayContext:
    institution_id: str
    institution_name: str
    plan_type: str
    role: str = "student"
    hashed_user_id: str | None = None


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    prefix = "bearer "
    value = authorization.strip()
    if value.lower().startswith(prefix):
        return value[len(prefix) :].strip() or None
    return None


def _fallback_api_key(settings: Settings) -> str:
    default_seed = settings.institution_seed_json.get(settings.default_institution_name, {})
    return str(default_seed.get("api_key", "")).strip()


def create_gateway_app(config: Settings | None = None) -> FastAPI:
    settings = config or default_settings
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        redis_client = build_redis_client(settings.redis_url, settings.redis_enabled)
        app.state.rate_limiter = RateLimiter(limit_per_minute=settings.rate_limit_per_minute, redis_client=redis_client)

        if settings.service_mode == "inprocess":
            db = Database(settings.database_url)
            auth_manager = AuthManager(settings=settings, db=db)
            auth_manager.bootstrap()
            metrics_manager = MetricsManager(settings=settings, db=db)
            metrics_manager.bootstrap()
            app.state.auth_manager = auth_manager
            app.state.inference_manager = InferenceManager(settings)
            app.state.explanation_manager = ExplanationManager(settings, CacheStore(redis_client))
            app.state.metrics_manager = metrics_manager
        else:
            app.state.inference_client = InternalServiceClient(
                base_url=settings.inference_service_url,
                internal_token=settings.internal_service_token,
                timeout_ms=settings.gateway_service_timeout_ms,
            )
            app.state.explanation_client = InternalServiceClient(
                base_url=settings.explanation_service_url,
                internal_token=settings.internal_service_token,
                timeout_ms=settings.gateway_service_timeout_ms,
            )
            app.state.metrics_client = InternalServiceClient(
                base_url=settings.metrics_service_url,
                internal_token=settings.internal_service_token,
                timeout_ms=settings.gateway_service_timeout_ms,
            )
            app.state.auth_client = InternalServiceClient(
                base_url=settings.auth_service_url,
                internal_token=settings.internal_service_token,
                timeout_ms=settings.gateway_service_timeout_ms,
            )
        logger.info("Gateway initialized in mode=%s", settings.service_mode)
        yield

    docs_url = "/docs" if settings.enable_docs else None
    redoc_url = "/redoc" if settings.enable_docs else None
    openapi_url = "/openapi.json" if settings.enable_docs else None
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )
    add_common_handlers(app, settings)
    add_prometheus(app, service_name="gateway")

    @app.middleware("http")
    async def _rate_limit(request: Request, call_next):
        if request.url.path in {"/healthz", "/readyz", "/metrics/prometheus"}:
            return await call_next(request)
        api_key = request.headers.get("X-API-Key", "no-key")
        client_ip = request.client.host if request.client else "unknown"
        key = f"{api_key}:{client_ip}"
        if not app.state.rate_limiter.allow(key):
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
        return await call_next(request)

    def resolve_context(
        authorization: str | None = Header(default=None, alias="Authorization"),
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ) -> GatewayContext:
        if settings.require_api_key and not x_api_key:
            raise HTTPException(status_code=401, detail="Missing API key")
        try:
            if settings.service_mode == "inprocess":
                auth_context: AuthContext = app.state.auth_manager.validate_api_key(x_api_key)
                base_context = GatewayContext(
                    institution_id=auth_context.institution_id,
                    institution_name=auth_context.institution_name,
                    plan_type=auth_context.plan_type,
                    role="student",
                    hashed_user_id=None,
                )
            else:
                api_key = x_api_key or _fallback_api_key(settings)
                payload = app.state.auth_client.post_json("/validate-api-key", {"api_key": api_key})
                auth_context = AuthContextResponse(**payload)
                base_context = GatewayContext(
                    institution_id=auth_context.institution_id,
                    institution_name=auth_context.institution_name,
                    plan_type=auth_context.plan_type,
                    role="student",
                    hashed_user_id=None,
                )
        except (ValueError, ServiceCallError) as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

        token = _extract_bearer_token(authorization)
        if not token:
            return base_context

        try:
            if settings.service_mode == "inprocess":
                token_context = app.state.auth_manager.validate_token(token)
                if token_context.institution_id != base_context.institution_id:
                    raise HTTPException(status_code=403, detail="Token does not match API key institution")
                return GatewayContext(
                    institution_id=token_context.institution_id,
                    institution_name=token_context.institution_name,
                    plan_type=token_context.plan_type,
                    role=token_context.role,
                    hashed_user_id=token_context.hashed_user_id,
                )

            payload = app.state.auth_client.post_json("/validate-token", {"token": token})
            token_context = AuthContextResponse(**payload)
            if token_context.institution_id != base_context.institution_id:
                raise HTTPException(status_code=403, detail="Token does not match API key institution")
            return GatewayContext(
                institution_id=token_context.institution_id,
                institution_name=token_context.institution_name,
                plan_type=token_context.plan_type,
                role=token_context.role,
                hashed_user_id=token_context.hashed_user_id,
            )
        except ServiceCallError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def run_inference(text: str, url: str) -> InferenceResponse:
        if settings.service_mode == "inprocess":
            return app.state.inference_manager.analyze(text=text, url=url)
        payload = app.state.inference_client.post_json("/analyze", {"text": text, "url": url})
        return InferenceResponse(**payload)

    def run_explanation(text: str, url: str, risk_score: float) -> ExplainResponse:
        if settings.service_mode == "inprocess":
            return app.state.explanation_manager.explain(text=text, url=url, risk_score=risk_score)
        payload = app.state.explanation_client.post_json(
            "/explain",
            {"text": text, "url": url, "risk_score": risk_score},
        )
        return ExplainResponse(**payload)

    def emit_metrics_event(
        *,
        institution_id: str,
        risk_score: float,
        risk_bucket: str,
        hashed_user_id: str | None,
    ) -> None:
        if settings.service_mode == "inprocess":
            app.state.metrics_manager.record_event(
                institution_id=institution_id,
                risk_score=risk_score,
                risk_bucket=risk_bucket,
                hashed_user_id=hashed_user_id,
            )
            return
        app.state.metrics_client.post_json(
            "/events",
            {
                "institution_id": institution_id,
                "risk_score": risk_score,
                "risk_bucket": risk_bucket,
                "hashed_user_id": hashed_user_id,
            },
        )

    def warm_explanation_cache(*, text: str, url: str, risk_score: float) -> None:
        try:
            run_explanation(text=text, url=url, risk_score=risk_score)
        except Exception as exc:  # pragma: no cover
            logger.debug("Explanation cache warmup failed: %s", exc)

    @app.get("/healthz")
    def healthz():
        return {
            "status": "ok",
            "service": "gateway",
            "mode": settings.service_mode,
            "demo_mode": settings.demo_mode,
        }

    @app.get("/readyz")
    def readyz():
        return {"ready": True, "mode": settings.service_mode}

    @app.get("/mode", response_model=RuntimeModeResponse)
    def mode():
        return RuntimeModeResponse(
            demo_mode=settings.demo_mode,
            api_key_required=settings.require_api_key,
            service_mode=settings.service_mode,  # type: ignore[arg-type]
            force_heuristic=settings.force_heuristic,
        )

    @app.post("/auth/token", response_model=TokenResponse)
    def issue_token(
        req: TokenRequest,
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ):
        if settings.require_api_key and not x_api_key:
            raise HTTPException(status_code=401, detail="Missing API key")
        if settings.service_mode == "inprocess":
            try:
                return app.state.auth_manager.issue_token(
                    api_key=x_api_key,
                    role=req.role,
                    hashed_user_id=app.state.auth_manager.normalize_hashed_user_id(req.hashed_user_id),
                )
            except ValueError as exc:
                raise HTTPException(status_code=401, detail=str(exc)) from exc

        try:
            response = httpx.post(
                f"{settings.auth_service_url.rstrip('/')}/token",
                json=req.model_dump(),
                headers={"X-API-Key": x_api_key or _fallback_api_key(settings)},
                timeout=settings.gateway_service_timeout_ms / 1000.0,
            )
            response.raise_for_status()
            return TokenResponse(**response.json())
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text) from exc
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=503, detail=f"Auth service unavailable: {exc}") from exc

    @app.post("/analyze", response_model=AnalyzeResponse)
    def analyze(req: AnalyzeRequest, background_tasks: BackgroundTasks, ctx: GatewayContext = Depends(resolve_context)):
        text = req.text
        url = str(req.url)
        if len(text) > settings.text_max_length:
            raise HTTPException(status_code=422, detail=f"text length exceeds {settings.text_max_length}")
        if len(url) > settings.url_max_length:
            raise HTTPException(status_code=422, detail=f"url length exceeds {settings.url_max_length}")

        try:
            inference = run_inference(text=text, url=url)
        except ServiceCallError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

        hashed_message_id = stable_message_fingerprint(text=text, url=url, hash_salt=settings.hash_salt)
        user_id_source = req.hashed_user_id or ctx.hashed_user_id
        hashed_user_id = hash_identifier(user_id_source, settings.hash_salt) if user_id_source else None

        background_tasks.add_task(
            emit_metrics_event,
            institution_id=ctx.institution_id,
            risk_score=inference.risk_score,
            risk_bucket=inference.risk_bucket,
            hashed_user_id=hashed_user_id,
        )
        background_tasks.add_task(
            warm_explanation_cache,
            text=text,
            url=url,
            risk_score=inference.risk_score,
        )

        return AnalyzeResponse(
            risk_score=inference.risk_score,
            prediction=inference.prediction,
            risk_bucket=inference.risk_bucket,
            inference_latency_ms=inference.inference_latency_ms,
            model_backend=inference.model_backend,
            hashed_id=hashed_message_id,
        )

    @app.post("/explain", response_model=ExplainResponse)
    def explain(req: AnalyzeRequest, ctx: GatewayContext = Depends(resolve_context)):
        del ctx
        text = req.text
        url = str(req.url)
        if len(text) > settings.text_max_length:
            raise HTTPException(status_code=422, detail=f"text length exceeds {settings.text_max_length}")
        if len(url) > settings.url_max_length:
            raise HTTPException(status_code=422, detail=f"url length exceeds {settings.url_max_length}")
        try:
            inference = run_inference(text=text, url=url)
            return run_explanation(text=text, url=url, risk_score=inference.risk_score)
        except ServiceCallError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.get("/metrics", response_model=MetricsResponse)
    def metrics(since_hours: int = 24 * 7, ctx: GatewayContext = Depends(resolve_context)):
        if not settings.demo_mode and ctx.role != "admin":
            raise HTTPException(status_code=403, detail="Admin role required")
        if settings.service_mode == "inprocess":
            summary = app.state.metrics_manager.get_summary(institution_id=ctx.institution_id, since_hours=since_hours)
            return MetricsResponse(
                institution_id=summary.institution_id,
                total_requests=summary.total_requests,
                avg_risk=summary.avg_risk,
                high_risk_rate=summary.high_risk_rate,
                buckets=summary.buckets,
            )
        try:
            payload = app.state.metrics_client.get_json(
                f"/aggregate/{ctx.institution_id}",
                params={"since_hours": since_hours},
            )
            summary = MetricsSummaryResponse(**payload)
            return MetricsResponse(
                institution_id=summary.institution_id,
                total_requests=summary.total_requests,
                avg_risk=summary.avg_risk,
                high_risk_rate=summary.high_risk_rate,
                buckets=summary.buckets,
            )
        except ServiceCallError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.get("/blacklist", response_model=BlacklistResponse)
    def blacklist(ctx: GatewayContext = Depends(resolve_context)):
        del ctx
        return BlacklistResponse(domains=sorted(set(settings.domain_blacklist)))

    return app
