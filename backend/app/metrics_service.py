from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header

from .config import Settings, settings as default_settings
from .http_utils import add_common_handlers, configure_logging, require_internal_token
from .metrics_logic import MetricsManager
from .observability import add_prometheus
from .schemas import MetricsEventRequest, MetricsSummaryResponse
from .storage import Database


def create_metrics_app(config: Settings | None = None) -> FastAPI:
    settings = config or default_settings
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        db = Database(settings.database_url)
        app.state.metrics = MetricsManager(settings=settings, db=db)
        app.state.metrics.bootstrap()
        yield

    docs_url = "/docs" if settings.enable_docs else None
    redoc_url = "/redoc" if settings.enable_docs else None
    openapi_url = "/openapi.json" if settings.enable_docs else None
    app = FastAPI(
        title="CyberSaarthi Metrics Service",
        version=settings.app_version,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )
    add_common_handlers(app, settings)
    add_prometheus(app, service_name="metrics")

    def internal_guard(x_internal_token: str | None = Header(default=None, alias="X-Internal-Token")):
        require_internal_token(settings, x_internal_token)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "metrics"}

    @app.get("/readyz")
    def readyz():
        return {"ready": True}

    @app.post("/events", dependencies=[Depends(internal_guard)])
    def ingest_event(req: MetricsEventRequest):
        app.state.metrics.record_event(
            institution_id=req.institution_id,
            risk_score=req.risk_score,
            risk_bucket=req.risk_bucket,
            hashed_user_id=req.hashed_user_id,
            event_time=req.event_time,
        )
        return {"status": "accepted"}

    @app.get("/aggregate/{institution_id}", response_model=MetricsSummaryResponse, dependencies=[Depends(internal_guard)])
    def aggregate(institution_id: str, since_hours: int = 24 * 7):
        return app.state.metrics.get_summary(institution_id=institution_id, since_hours=since_hours)

    return app


app = create_metrics_app()
