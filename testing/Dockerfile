# ==============================================================================
# ULPF Testing Simulator & Protocol Testing Hub
# Dedicated testing website, socket probe, and network simulator for ULPF
# ==============================================================================

FROM python:3.12-slim

# Image metadata
LABEL org.opencontainers.image.title="ULPF Testing Simulator Hub" \
      org.opencontainers.image.description="Dedicated testing website and network connection simulator for Universal Log Pre-processing Framework" \
      org.opencontainers.image.version="1.0.0"

# Set environment variables:
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TESTING_HOST=0.0.0.0 \
    TESTING_PORT=8050 \
    ULPF_INTERNAL_API_HOST=host.docker.internal \
    PYTHONPATH=/app/testing:/app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root system user
RUN groupadd -r appuser && useradd -r -u 1000 -g appuser -d /app appuser

# Set working directory
WORKDIR /app

# Install Python dependencies first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create storage dirs and set permissions
RUN mkdir -p /app/storage/raw /app/storage/logs && chown -R appuser:appuser /app

# Copy application source code into container
COPY --chown=appuser:appuser . .

# Switch to non-root user
USER appuser

# Expose Simulator Web Application Port
EXPOSE 8050

# Healthcheck
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8050}/ || exit 1

# Launch the Simulator Hub
CMD ["python", "run_testing.py"]
