# ==============================================================================
# ULPF — Universal Log Pre-processing Framework
# Dedicated Main SOC Backend & Dashboard Container Image (for VM / Host Deployment)
# ==============================================================================

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    ULPF_ENV=production \
    ULPF_API_HOST=0.0.0.0 \
    ULPF_API_PORT=8000 \
    PYTHONPATH=/app

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create deterministic non-root system user & group (UID/GID 10001) for volume permission consistency
RUN groupadd -r -g 10001 ulpfgroup && useradd -r -u 10001 -g ulpfgroup -d /app -s /sbin/nologin ulpfuser
RUN mkdir -p /app/storage/raw /app/storage/logs && chown -R ulpfuser:ulpfgroup /app

COPY --chown=ulpfuser:ulpfgroup . .

USER ulpfuser

EXPOSE 8000
EXPOSE 5140/udp
EXPOSE 5141

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD curl -f -s http://127.0.0.1:8000/api/v1/health/live || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-${ULPF_API_PORT:-8000}} --no-access-log"]
