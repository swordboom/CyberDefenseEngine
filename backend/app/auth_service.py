from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException

from .auth_logic import AuthManager
from .config import Settings, settings as default_settings
from .http_utils import add_common_handlers, configure_logging, require_internal_token
from .observability import add_prometheus
from .schemas import (
    ApiKeyValidationRequest,
    AuthContextResponse,
    TokenRequest,
    TokenResponse,
    TokenValidationRequest,
)
from .storage import Database


def create_auth_app(config: Settings | None = None) -> FastAPI:
    settings = config or default_settings
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        db = Database(settings.database_url)
        app.state.auth_manager = AuthManager(settings=settings, db=db)
        app.state.auth_manager.bootstrap()
        yield

    docs_url = "/docs" if settings.enable_docs else None
    redoc_url = "/redoc" if settings.enable_docs else None
    openapi_url = "/openapi.json" if settings.enable_docs else None
    app = FastAPI(
        title="CyberSaarthi Auth Service",
        version=settings.app_version,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )
    add_common_handlers(app, settings)
    add_prometheus(app, service_name="auth")

    def internal_guard(x_internal_token: str | None = Header(default=None, alias="X-Internal-Token")):
        require_internal_token(settings, x_internal_token)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "auth"}

    @app.get("/readyz")
    def readyz():
        return {"ready": True}

    @app.post("/token", response_model=TokenResponse)
    def issue_token(
        req: TokenRequest,
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ):
        try:
            return app.state.auth_manager.issue_token(
                api_key=x_api_key,
                role=req.role,
                hashed_user_id=app.state.auth_manager.normalize_hashed_user_id(req.hashed_user_id),
            )
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    @app.post("/validate-api-key", response_model=AuthContextResponse, dependencies=[Depends(internal_guard)])
    def validate_api_key(req: ApiKeyValidationRequest):
        try:
            context = app.state.auth_manager.validate_api_key(req.api_key)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return context.to_response()

    @app.post("/validate-token", response_model=AuthContextResponse, dependencies=[Depends(internal_guard)])
    def validate_token(req: TokenValidationRequest):
        try:
            context = app.state.auth_manager.validate_token(req.token)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return context.to_response()

    return app


app = create_auth_app()
