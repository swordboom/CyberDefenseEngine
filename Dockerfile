FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    OMP_PROC_BIND=TRUE \
    OMP_PLACES=cores

WORKDIR /app

COPY backend/requirements*.txt /app/backend/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/backend/requirements.txt && \
    pip install --no-cache-dir -r /app/backend/requirements-ml.txt

COPY backend /app/backend

RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

ENV SERVICE_APP=backend.app.main:app \
    PORT=8000 \
    WORKERS=4

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"

CMD ["bash", "-lc", "gunicorn ${SERVICE_APP} -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:${PORT} --workers 1 --worker-tmp-dir /dev/shm --timeout 120 --graceful-timeout 30 --keep-alive 5 --access-logfile - --error-logfile -"]
