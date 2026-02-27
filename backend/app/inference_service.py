from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header

from .config import Settings, settings as default_settings
from .http_utils import add_common_handlers, configure_logging, require_internal_token
from .inference_logic import InferenceManager
from .observability import add_prometheus
from .schemas import InferenceBatchRequest, InferenceBatchResponse, InferenceRequest, InferenceResponse


def create_inference_app(config: Settings | None = None) -> FastAPI:
    settings = config or default_settings
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        app.state.inference = InferenceManager(settings)
        yield

    docs_url = "/docs" if settings.enable_docs else None
    redoc_url = "/redoc" if settings.enable_docs else None
    openapi_url = "/openapi.json" if settings.enable_docs else None
    app = FastAPI(
        title="CyberDefenseEngine Inference Service",
        version=settings.app_version,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )
    add_common_handlers(app, settings)
    add_prometheus(app, service_name="inference")

    def internal_guard(x_internal_token: str | None = Header(default=None, alias="X-Internal-Token")):
        require_internal_token(settings, x_internal_token)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "inference"}

    @app.get("/readyz")
    def readyz():
        return {"ready": True}

    @app.post("/analyze", response_model=InferenceResponse, dependencies=[Depends(internal_guard)])
    def analyze(req: InferenceRequest):
        return app.state.inference.analyze(text=req.text, url=str(req.url))

    @app.post("/analyze-batch", response_model=InferenceBatchResponse, dependencies=[Depends(internal_guard)])
    def analyze_batch(req: InferenceBatchRequest):
        items = [(item.text, str(item.url)) for item in req.items]
        responses = app.state.inference.analyze_batch(items=items)
        return InferenceBatchResponse(items=responses)

    return app


app = create_inference_app()
