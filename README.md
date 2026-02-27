# CyberSaarthi

CyberSaarthi is now structured as a privacy-first microservice platform for phishing detection:

- `gateway` (API Gateway + orchestration)
- `inference` (ONNX/Torch/heuristic risk scoring)
- `explanation` (cached explainability output)
- `metrics` (aggregate-only analytics, multi-tenant safe)
- `auth` (institution API keys + JWT role tokens)

No raw phishing message content is persisted to storage.

## Architecture

```text
Chrome Extension / Frontend
        |
        v
API Gateway (FastAPI)
  |- Auth Service (JWT + API key validation)
  |- Inference Service (ONNX Runtime)
  |- Explanation Service (cached explanations)
  |- Metrics Service (aggregate-only writes)
        |
        +--> PostgreSQL (institutions, aggregated_metrics, users trend)
        +--> Redis (rate limiting + cache)
        +--> Prometheus/Grafana (observability)
```

## Repo Layout

```text
backend/
  app/
    main.py                 # Gateway entrypoint
    gateway.py
    auth_service.py
    inference_service.py
    explanation_service.py
    metrics_service.py
    auth_logic.py
    inference_logic.py
    explanation_logic.py
    metrics_logic.py
    storage.py
    security.py
    redis_utils.py
    observability.py
    config.py
    model.py
    explain.py
    privacy.py
    schemas.py
frontend/
extension/
deploy/monitoring/prometheus.yml
docker-compose.yml
Dockerfile
```

## Local Development (single-process mode)

Default `service_mode` is `inprocess`, so you can run one API for dev/testing.

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API endpoints:

- `POST /auth/token`
- `POST /analyze`
- `POST /explain`
- `GET /metrics` (requires admin JWT role)
- `GET /blacklist`
- `GET /healthz`
- `GET /readyz`
- `GET /metrics/prometheus`

## Production Deployment (microservices)

1. Copy env template:

```bash
cp backend/.env.example backend/.env
```

2. Set secure secrets in `backend/.env`:

- `HASH_SALT`
- `JWT_SECRET`
- `INTERNAL_SERVICE_TOKEN`
- `INSTITUTION_SEED_JSON`

3. Start stack:

```bash
docker compose up --build -d
```

Exposed services:

- Gateway: `http://127.0.0.1:8000`
- Prometheus: `http://127.0.0.1:9090`
- Grafana: `http://127.0.0.1:3001`

## Multi-Tenancy + Privacy Rules

- Institution scope is resolved from `X-API-Key`.
- JWT tokens carry `institution_id` + `role` (`student` or `admin`).
- Metrics are partitioned by `institution_id`.
- `GET /metrics` enforces `admin` role.
- Stored analytics are aggregated counts/risk sums only.
- Identifiers are SHA-256 hashed before persistence.
- Raw message text is never stored in DB.

## AMD/ONNX Runtime Performance Controls

Tune via env vars:

- `ONNX_INTRA_OP_THREADS`
- `ONNX_INTER_OP_THREADS`
- `ONNX_PROVIDERS`
- Gunicorn worker count per service (`WORKERS`)

ONNX graph optimization is enabled at `ORT_ENABLE_ALL`.

## Tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest -q
```

## Frontend

Static dashboard:

```bash
cd frontend
python -m http.server 5173
```

Open `http://127.0.0.1:5173`.

## Chrome Extension

The extension now includes:

- Background blacklist sync (`chrome.alarms`)
- Cached blacklist checks
- Backend scoring when available
- Local heuristic fallback when backend is down
