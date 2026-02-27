from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def _make_client(tmp_path, **overrides) -> TestClient:
    config = Settings(
        database_url=f"sqlite:///{tmp_path / 'cyberdefenseengine.db'}",
        service_mode="inprocess",
        force_heuristic=True,
        enable_docs=True,
        enable_gzip=False,
        trusted_hosts=["testserver", "localhost", "127.0.0.1"],
        cors_allow_origins=["http://localhost:3000"],
        **overrides,
    )
    return TestClient(create_app(config))


def _admin_headers(client: TestClient, api_key: str | None = None) -> dict[str, str]:
    token_response = client.post(
        "/auth/token",
        json={"role": "admin"},
        headers={"X-API-Key": api_key} if api_key else None,
    )
    assert token_response.status_code == 200
    token = token_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    if api_key:
        headers["X-API-Key"] = api_key
    return headers


def test_analyze_returns_expected_shape(tmp_path):
    with _make_client(tmp_path) as client:
        response = client.post(
            "/analyze",
            json={"text": "Your invoice is attached", "url": "https://company.com/invoice/123"},
        )
    assert response.status_code == 200
    body = response.json()
    assert 0.0 <= body["risk_score"] <= 1.0
    assert body["prediction"] in {"benign", "phishing"}
    assert body["risk_bucket"] in {"low", "medium", "high", "critical"}
    assert len(body["hashed_id"]) == 64


def test_invalid_url_is_rejected(tmp_path):
    with _make_client(tmp_path) as client:
        response = client.post("/analyze", json={"text": "hello", "url": "not-a-url"})
    assert response.status_code == 422


def test_empty_text_is_allowed_for_url_only_scan(tmp_path):
    with _make_client(tmp_path) as client:
        response = client.post("/analyze", json={"text": "   ", "url": "https://example.com"})
    assert response.status_code == 200


def test_metrics_increment_with_analyze_calls(tmp_path):
    with _make_client(tmp_path) as client:
        admin_headers = _admin_headers(client)
        client.post("/analyze", json={"text": "normal update", "url": "https://example.com"})
        client.post("/analyze", json={"text": "verify account now", "url": "http://verify-example.com"})
        metrics = client.get("/metrics", headers=admin_headers)

    assert metrics.status_code == 200
    payload = metrics.json()
    assert payload["total_requests"] == 2
    assert 0.0 <= payload["avg_risk"] <= 1.0
    assert 0.0 <= payload["high_risk_rate"] <= 1.0
    assert "buckets" in payload


def test_api_key_enforcement(tmp_path):
    with _make_client(
        tmp_path,
        require_api_key=True,
        institution_seed_json={"org": {"api_key": "secret-token", "plan_type": "pro"}},
        default_institution_name="org",
    ) as client:
        unauthorized = client.post("/analyze", json={"text": "hello", "url": "https://example.com"})
        authorized = client.post(
            "/analyze",
            json={"text": "hello", "url": "https://example.com"},
            headers={"X-API-Key": "secret-token"},
        )

    assert unauthorized.status_code == 401
    assert authorized.status_code == 200


def test_rate_limit_returns_429(tmp_path):
    with _make_client(tmp_path, rate_limit_per_minute=2) as client:
        first = client.post("/analyze", json={"text": "one", "url": "https://example.com/1"})
        second = client.post("/analyze", json={"text": "two", "url": "https://example.com/2"})
        third = client.post("/analyze", json={"text": "three", "url": "https://example.com/3"})

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429


def test_health_and_ready_endpoints(tmp_path):
    with _make_client(tmp_path) as client:
        health = client.get("/healthz")
        ready = client.get("/readyz")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert ready.status_code == 200
    assert ready.json()["ready"] is True


def test_metrics_requires_admin_role(tmp_path):
    with _make_client(tmp_path) as client:
        token_response = client.post("/auth/token", json={"role": "student"})
        token = token_response.json()["access_token"]
        response = client.get("/metrics", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_runtime_mode_endpoint(tmp_path):
    with _make_client(tmp_path, demo_mode=True, require_api_key=False) as client:
        response = client.get("/mode")
    assert response.status_code == 200
    payload = response.json()
    assert payload["demo_mode"] is True
    assert payload["api_key_required"] is False
    assert payload["force_heuristic"] is True


def test_demo_mode_metrics_without_admin_token(tmp_path):
    with _make_client(tmp_path, demo_mode=True, require_api_key=False) as client:
        analyze = client.post("/analyze", json={"text": "verify now", "url": "http://example.com/login"})
        metrics = client.get("/metrics")
    assert analyze.status_code == 200
    assert metrics.status_code == 200
