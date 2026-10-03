# VibeShield OpenShell task image — matches Layer-1 podman workload expectations
# (python entrypoint allowlist + ephemeral /workspace), pinned base.
FROM ubuntu:24.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-minimal ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /workspace && chown 1000:1000 /workspace

USER 1000
WORKDIR /workspace
