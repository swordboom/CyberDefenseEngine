import logging
import time
import uuid

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import Settings


def configure_logging(log_level: str) -> None:
    level = getattr(logging, log_level.upper(), logging.INFO)
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    root_logger.setLevel(level)


def add_common_handlers(app: FastAPI, settings: Settings) -> None:
    if settings.trusted_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=False,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
    )
    if settings.enable_gzip:
        app.add_middleware(GZipMiddleware, minimum_size=1024)

    @app.middleware("http")
    async def _request_headers(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > settings.max_payload_bytes:
                    return JSONResponse(status_code=413, content={"detail": "Payload too large"})
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid content-length header"})

        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            logging.getLogger(__name__).exception("Unhandled exception request_id=%s path=%s", request_id, request.url.path)
            return JSONResponse(status_code=500, content={"detail": "Internal server error", "request_id": request_id})
        latency_ms = (time.perf_counter() - start) * 1000
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time-Ms"] = f"{latency_ms:.2f}"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"
        return response

    @app.exception_handler(RequestValidationError)
    async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
        request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
        return JSONResponse(
            status_code=422,
            content={"detail": jsonable_encoder(exc.errors()), "request_id": request_id},
        )


def require_internal_token(settings: Settings, x_internal_token: str | None = Header(default=None, alias="X-Internal-Token")):
    if x_internal_token != settings.internal_service_token:
        raise HTTPException(status_code=401, detail="Invalid internal service token")
