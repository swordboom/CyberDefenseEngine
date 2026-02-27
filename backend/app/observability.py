import time

from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

REQUEST_COUNT = Counter(
    "cybersaarthi_http_requests_total",
    "HTTP requests served",
    ["service", "method", "path", "status_code"],
)
REQUEST_LATENCY = Histogram(
    "cybersaarthi_http_request_duration_seconds",
    "HTTP latency seconds",
    ["service", "path"],
)


def add_prometheus(app: FastAPI, *, service_name: str) -> None:
    @app.middleware("http")
    async def _record_metrics(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start
        path = request.url.path
        REQUEST_COUNT.labels(
            service=service_name,
            method=request.method,
            path=path,
            status_code=response.status_code,
        ).inc()
        REQUEST_LATENCY.labels(service=service_name, path=path).observe(duration)
        return response

    @app.get("/metrics/prometheus")
    def prometheus_metrics() -> Response:
        data = generate_latest()
        return Response(content=data, media_type=CONTENT_TYPE_LATEST)
