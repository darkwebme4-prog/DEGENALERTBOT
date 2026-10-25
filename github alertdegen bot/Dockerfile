# Multi-Chain EVM NFT Mint Radar & Alert Bot
FROM python:3.12-slim

# Prevent Python from writing .pyc files and buffering stdout/stderr
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies (curl for container healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user
RUN groupadd -g 1000 alertbot && \
    useradd -u 1000 -g alertbot -m -s /bin/bash alertbot

WORKDIR /app

# Install project dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir .

# Copy application source code and configuration files
COPY app/ ./app/
COPY chains.yaml risk.yaml quality.yaml ./

# Create data and logs directories with proper permissions
RUN mkdir -p /app/data /app/logs && \
    chown -R alertbot:alertbot /app

USER alertbot

# Expose HTTP health check endpoint
EXPOSE 8080

# Container healthcheck querying local endpoint (evaluates dynamic $PORT on platforms like Railway)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/health || exit 1

# Start the alert bot
ENTRYPOINT ["python", "-m", "app.main"]
