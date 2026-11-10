FROM python:3.13-slim

WORKDIR /app
COPY . .

RUN python3 -m venv /app/.venv \
    && /app/.venv/bin/pip install --upgrade pip \
    && /app/.venv/bin/pip install --no-cache-dir -r requirements-docker.txt

RUN mkdir -p /app/logs && chmod 700 /app/logs

ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

# Bind to all container interfaces; host exposure remains controlled by Compose/network policy.
CMD ["sh", "-c", "python3 -m uvicorn backend.app.main:app --host ${UVICORN_HOST:-0.0.0.0} --port ${UVICORN_PORT:-8000}"]
