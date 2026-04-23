# Rootless OCI-compliant base image for the Kraken Security Framework
# Built on Podman — no root daemon required

FROM python:3.11-slim

# Security: run as non-root user
RUN groupadd -r kraken && useradd -r -g kraken -d /home/kraken -s /sbin/nologin kraken

# Minimal dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    podman \
    crun \
    && rm -rf /var/lib/apt/lists/*

# Create workspace
WORKDIR /app

# Copy requirements first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Copy framework code
COPY core/ ./core/
COPY api/ ./api/

# Drop to non-root user
USER kraken

# Security: no new privileges, read-only rootfs except /tmp
VOLUME ["/tmp/agent-workspace"]

# Agent entry point receives encrypted payload as argument
ENTRYPOINT ["python", "-m", "core.layer1_sandbox"]

# Default: no network, all caps dropped (enforced at runtime by the orchestrator)
