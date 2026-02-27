from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header

from .config import Settings, settings as default_settings
from .explanation_logic import ExplanationManager
from .http_utils import add_common_handlers, configure_logging, require_internal_token
from .observability import add_prometheus
from .redis_utils import CacheStore, build_redis_client
from .schemas import ExplainRequest, ExplainResponse


def create_explanation_app(config: Settings | None = None) -> FastAPI:
    settings = config or default_settings
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        redis_client = build_redis_client(settings.redis_url, settings.redis_enabled)
        cache = CacheStore(redis_client)
        app.state.explainer = ExplanationManager(settings, cache)
        yield

    docs_url = "/docs" if settings.enable_docs else None
    redoc_url = "/redoc" if settings.enable_docs else None
    openapi_url = "/openapi.json" if settings.enable_docs else None
    app = FastAPI(
        title="CyberDefenseEngine Explanation Service",
        version=settings.app_version,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )
    add_common_handlers(app, settings)
    add_prometheus(app, service_name="explanation")

    def internal_guard(x_internal_token: str | None = Header(default=None, alias="X-Internal-Token")):
        require_internal_token(settings, x_internal_token)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "explanation"}

    @app.get("/readyz")
    def readyz():
        return {"ready": True}

    @app.post("/explain", response_model=ExplainResponse, dependencies=[Depends(internal_guard)])
    def explain(req: ExplainRequest):
        return app.state.explainer.explain(text=req.text, url=str(req.url), risk_score=req.risk_score)

    return app


app = create_explanation_app()
